#!/usr/bin/env python3
"""
ML-Enhanced Vulnerability Classifier for AODS

Integrates machine learning models with organic vulnerability detection
to improve accuracy, reduce false positives, and provide confidence scoring.

Features:
- ML prediction integration with organic results
- Confidence-based filtering and scoring
- False positive reduction using ML models
- Vulnerability classification enhancement
- Ground truth validation integration
"""

import os
import json
import logging
import pickle
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ClassificationResult(Enum):
    """ML classification results"""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"
    FRAMEWORK_FILE = "framework_file"

@dataclass
class MLPrediction:
    """ML prediction result"""
    classification: ClassificationResult
    confidence: float
    reasoning: str
    features_used: List[str]
    organic_agreement: bool

@dataclass 
class EnhancedVulnerability:
    """Vulnerability enhanced with ML predictions"""
    original_finding: Dict[str, Any]
    ml_prediction: MLPrediction
    final_classification: ClassificationResult
    confidence_score: float
    recommendation: str

class MLEnhancedClassifier:
    """Main ML-enhanced vulnerability classifier"""
    
    def __init__(self, models_dir: str = "ml/models"):
        self.models_dir = Path(models_dir)
        self.xgb_model = None
        self.feature_extractor = None
        self.label_encoder = None
        self.confidence_threshold = 0.7
        self.false_positive_threshold = 0.3
        self.initialized = False
        
        # ML enhancement statistics
        self.stats = {
            "total_processed": 0,
            "ml_enhanced": 0,
            "false_positives_filtered": 0,
            "confidence_improved": 0,
            "organic_agreement": 0
        }
        
    def initialize(self) -> bool:
        """Initialize ML models and components"""
        try:
            if not self.models_dir.exists():
                logger.warning(f"Models directory not found: {self.models_dir}")
                return False
            
            # Load models if available
            model_files = {
                "xgboost_vulnerability_classifier.pkl": "xgb_model",
                "feature_extractor.pkl": "feature_extractor", 
                "label_encoder.pkl": "label_encoder"
            }
            
            models_loaded = 0
            for file_name, attr_name in model_files.items():
                file_path = self.models_dir / file_name
                if file_path.exists():
                    with open(file_path, 'rb') as f:
                        setattr(self, attr_name, pickle.load(f))
                    models_loaded += 1
                    logger.info(f"Loaded {file_name}")
            
            if models_loaded == len(model_files):
                self.initialized = True
                logger.info("ML classifier fully initialized")
                return True
            else:
                logger.warning(f"Only {models_loaded}/{len(model_files)} models loaded")
                return False
                
        except Exception as e:
            logger.error(f"Failed to initialize ML classifier: {e}")
            return False
    
    def enhance_vulnerability_detection(self, vulnerabilities: List[Dict[str, Any]]) -> List[EnhancedVulnerability]:
        """Enhance vulnerability detection with ML predictions"""
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            self.stats["total_processed"] += 1
            
            try:
                # Get ML prediction
                ml_prediction = self._get_ml_prediction(vuln)
                
                # Determine final classification
                final_classification = self._determine_final_classification(vuln, ml_prediction)
                
                # Calculate confidence score
                confidence_score = self._calculate_confidence_score(vuln, ml_prediction)
                
                # Generate recommendation
                recommendation = self._generate_recommendation(vuln, ml_prediction, final_classification)
                
                # Create enhanced vulnerability
                enhanced_vuln = EnhancedVulnerability(
                    original_finding=vuln,
                    ml_prediction=ml_prediction,
                    final_classification=final_classification,
                    confidence_score=confidence_score,
                    recommendation=recommendation
                )
                
                enhanced_vulns.append(enhanced_vuln)
                
                # Update statistics
                self._update_statistics(ml_prediction, final_classification)
                
            except Exception as e:
                logger.error(f"Failed to enhance vulnerability {vuln.get('id', 'unknown')}: {e}")
                # Fallback to original classification
                enhanced_vuln = self._create_fallback_enhancement(vuln)
                enhanced_vulns.append(enhanced_vuln)
        
        logger.info(f"Enhanced {len(enhanced_vulns)} vulnerabilities with ML predictions")
        return enhanced_vulns
    
    def _get_ml_prediction(self, vulnerability: Dict[str, Any]) -> MLPrediction:
        """Get ML prediction for a vulnerability"""
        
        if not self.initialized:
            return self._create_fallback_prediction(vulnerability, "ML models not initialized")
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features([vulnerability])
            
            # Get prediction
            prediction_proba = self.xgb_model.predict_proba(features.reshape(1, -1))[0]
            predicted_class_idx = np.argmax(prediction_proba)
            confidence = prediction_proba[predicted_class_idx]
            
            # Decode label
            predicted_label = self.label_encoder.inverse_transform([predicted_class_idx])[0]
            
            # Map to classification result
            classification_map = {
                "true_positive": ClassificationResult.TRUE_POSITIVE,
                "false_positive": ClassificationResult.FALSE_POSITIVE,
                "uncertain": ClassificationResult.UNCERTAIN
            }
            
            classification = classification_map.get(predicted_label, ClassificationResult.UNCERTAIN)
            
            # Determine organic agreement
            organic_classification = self._get_organic_classification(vulnerability)
            organic_agreement = classification == organic_classification
            
            if organic_agreement:
                self.stats["organic_agreement"] += 1
            
            return MLPrediction(
                classification=classification,
                confidence=confidence,
                reasoning=f"ML model prediction: {predicted_label} with {confidence:.3f} confidence",
                features_used=["text_features", "metadata_features", "security_patterns"],
                organic_agreement=organic_agreement
            )
            
        except Exception as e:
            return self._create_fallback_prediction(vulnerability, f"ML prediction failed: {e}")
    
    def _get_organic_classification(self, vulnerability: Dict[str, Any]) -> ClassificationResult:
        """Determine organic classification based on patterns"""
        title = vulnerability.get("title", "").lower()
        description = vulnerability.get("description", "").lower()
        
        # Clear false positive patterns
        fp_patterns = [
            "❌" in title and "failed" in description,
            "completed" in description and "no vulnerabilities found" in description,
            "status: pass" in description,
            "information extraction" in title,
            "certificate analysis" in title,
            "application is not debuggable" in description
        ]
        
        if any(fp_patterns):
            return ClassificationResult.FALSE_POSITIVE
        
        # Clear true positive patterns
        tp_patterns = [
            "sql injection" in description and "found" in description,
            "insecure storage" in description and "plaintext" in description,
            "weak crypto" in description,
            "hardcoded" in description and ("key" in description or "password" in description),
            "exported component" in description and "dangerous" in description
        ]
        
        if any(tp_patterns):
            return ClassificationResult.TRUE_POSITIVE
        
        # Framework file patterns
        framework_patterns = [
            "android/support" in description,
            "androidx" in description,
            "framework" in title.lower(),
            "library" in title.lower()
        ]
        
        if any(framework_patterns):
            return ClassificationResult.FRAMEWORK_FILE
        
        return ClassificationResult.UNCERTAIN
    
    def _determine_final_classification(self, vulnerability: Dict[str, Any], ml_prediction: MLPrediction) -> ClassificationResult:
        """Determine final classification combining ML and organic analysis"""
        
        organic_classification = self._get_organic_classification(vulnerability)
        
        # High confidence ML predictions take precedence
        if ml_prediction.confidence > self.confidence_threshold:
            if ml_prediction.classification == ClassificationResult.FALSE_POSITIVE:
                return ClassificationResult.FALSE_POSITIVE
        
        # Agreement between ML and organic
        if ml_prediction.organic_agreement and ml_prediction.confidence > 0.5:
            return ml_prediction.classification
        
        # Conservative approach for disagreements
        if (organic_classification == ClassificationResult.FALSE_POSITIVE and 
            ml_prediction.classification == ClassificationResult.FALSE_POSITIVE):
            return ClassificationResult.FALSE_POSITIVE
        
        if (organic_classification == ClassificationResult.TRUE_POSITIVE and
            ml_prediction.classification == ClassificationResult.TRUE_POSITIVE):
            return ClassificationResult.TRUE_POSITIVE
        
        # When uncertain, defer to organic classification if clear
        if organic_classification != ClassificationResult.UNCERTAIN:
            return organic_classification
        
        # Default to ML prediction for uncertain cases
        return ml_prediction.classification
    
    def _calculate_confidence_score(self, vulnerability: Dict[str, Any], ml_prediction: MLPrediction) -> float:
        """Calculate overall confidence score"""
        
        # Base confidence from ML model
        ml_confidence = ml_prediction.confidence
        
        # Adjust based on organic agreement
        agreement_bonus = 0.1 if ml_prediction.organic_agreement else -0.1
        
        # Adjust based on clear patterns
        title = vulnerability.get("title", "").lower()
        description = vulnerability.get("description", "").lower()
        
        # High confidence adjustments
        high_confidence_patterns = [
            "❌" in title and "failed" in description,  # Clear plugin error
            "status: pass" in description,  # Clear PASS result
            "no vulnerabilities found" in description  # Clear negative result
        ]
        
        if any(high_confidence_patterns):
            pattern_bonus = 0.2
        else:
            pattern_bonus = 0.0
        
        # Calculate final confidence
        final_confidence = min(1.0, max(0.0, ml_confidence + agreement_bonus + pattern_bonus))
        
        return final_confidence
    
    def _generate_recommendation(self, vulnerability: Dict[str, Any], ml_prediction: MLPrediction, 
                               final_classification: ClassificationResult) -> str:
        """Generate recommendation based on classification"""
        
        if final_classification == ClassificationResult.FALSE_POSITIVE:
            if ml_prediction.confidence > 0.8:
                return "HIGH CONFIDENCE: Filter as false positive - likely plugin error or informational result"
            else:
                return "MEDIUM CONFIDENCE: Review for false positive - may be misclassified informational result"
        
        elif final_classification == ClassificationResult.TRUE_POSITIVE:
            if ml_prediction.confidence > 0.8:
                return "HIGH CONFIDENCE: Investigate as potential vulnerability - manual verification recommended"
            else:
                return "MEDIUM CONFIDENCE: Review for vulnerability - requires detailed analysis"
        
        elif final_classification == ClassificationResult.FRAMEWORK_FILE:
            return "Framework/library code detected - apply enhanced filtering, exclude from vulnerability analysis"
        
        else:  # UNCERTAIN
            return "UNCERTAIN: Manual review required - insufficient confidence for automated classification"
    
    def _update_statistics(self, ml_prediction: MLPrediction, final_classification: ClassificationResult):
        """Update ML enhancement statistics"""
        
        if ml_prediction.confidence > 0.5:
            self.stats["ml_enhanced"] += 1
        
        if final_classification == ClassificationResult.FALSE_POSITIVE:
            self.stats["false_positives_filtered"] += 1
        
        if ml_prediction.confidence > self.confidence_threshold:
            self.stats["confidence_improved"] += 1
    
    def _create_fallback_prediction(self, vulnerability: Dict[str, Any], reason: str) -> MLPrediction:
        """Create fallback prediction when ML models unavailable"""
        
        organic_classification = self._get_organic_classification(vulnerability)
        
        return MLPrediction(
            classification=organic_classification,
            confidence=0.5,  # Medium confidence for organic-only
            reasoning=f"Organic classification only: {reason}",
            features_used=["organic_patterns"],
            organic_agreement=True  # Perfect agreement with itself
        )
    
    def _create_fallback_enhancement(self, vulnerability: Dict[str, Any]) -> EnhancedVulnerability:
        """Create fallback enhancement when ML processing fails"""
        
        fallback_prediction = self._create_fallback_prediction(vulnerability, "Processing failed")
        
        return EnhancedVulnerability(
            original_finding=vulnerability,
            ml_prediction=fallback_prediction,
            final_classification=fallback_prediction.classification,
            confidence_score=0.5,
            recommendation="Manual review recommended - ML enhancement unavailable"
        )
    
    def filter_false_positives(self, enhanced_vulnerabilities: List[EnhancedVulnerability], 
                             strict_mode: bool = False) -> List[EnhancedVulnerability]:
        """Filter false positives based on ML predictions"""
        
        filtered_vulns = []
        filtered_count = 0
        
        for enhanced_vuln in enhanced_vulnerabilities:
            should_filter = False
            
            if strict_mode:
                # Strict filtering - high confidence required
                should_filter = (
                    enhanced_vuln.final_classification == ClassificationResult.FALSE_POSITIVE and
                    enhanced_vuln.confidence_score > 0.8
                )
            else:
                # Standard filtering - medium confidence sufficient
                should_filter = (
                    enhanced_vuln.final_classification == ClassificationResult.FALSE_POSITIVE and
                    enhanced_vuln.confidence_score > 0.6
                )
            
            if not should_filter:
                filtered_vulns.append(enhanced_vuln)
            else:
                filtered_count += 1
                logger.debug(f"Filtered false positive: {enhanced_vuln.original_finding.get('title', 'Unknown')}")
        
        logger.info(f"Filtered {filtered_count} false positives, {len(filtered_vulns)} vulnerabilities remain")
        return filtered_vulns
    
    def get_enhancement_statistics(self) -> Dict[str, Any]:
        """Get ML enhancement statistics"""
        
        total = self.stats["total_processed"]
        
        return {
            "total_processed": total,
            "ml_enhancement_rate": self.stats["ml_enhanced"] / total if total > 0 else 0,
            "false_positive_filter_rate": self.stats["false_positives_filtered"] / total if total > 0 else 0,
            "confidence_improvement_rate": self.stats["confidence_improved"] / total if total > 0 else 0,
            "organic_agreement_rate": self.stats["organic_agreement"] / total if total > 0 else 0,
            "models_initialized": self.initialized
        }
    
    def generate_enhancement_report(self, enhanced_vulnerabilities: List[EnhancedVulnerability]) -> Dict[str, Any]:
        """Generate comprehensive ML enhancement report"""
        
        # Classification distribution
        classification_counts = {}
        confidence_distribution = []
        
        for enhanced_vuln in enhanced_vulnerabilities:
            classification = enhanced_vuln.final_classification.value
            classification_counts[classification] = classification_counts.get(classification, 0) + 1
            confidence_distribution.append(enhanced_vuln.confidence_score)
        
        # Calculate metrics
        total_vulns = len(enhanced_vulnerabilities)
        avg_confidence = np.mean(confidence_distribution) if confidence_distribution else 0
        high_confidence_count = sum(1 for c in confidence_distribution if c > 0.8)
        
        stats = self.get_enhancement_statistics()
        
        report = {
            "enhancement_summary": {
                "total_vulnerabilities": total_vulns,
                "average_confidence": avg_confidence,
                "high_confidence_predictions": high_confidence_count,
                "classification_distribution": classification_counts
            },
            "ml_performance": stats,
            "quality_metrics": {
                "predicted_false_positive_rate": classification_counts.get("false_positive", 0) / total_vulns if total_vulns > 0 else 0,
                "confident_predictions_rate": high_confidence_count / total_vulns if total_vulns > 0 else 0,
                "organic_ml_agreement_rate": stats["organic_agreement_rate"]
            },
            "recommendations": self._generate_enhancement_recommendations(stats, classification_counts)
        }
        
        return report
    
    def _generate_enhancement_recommendations(self, stats: Dict[str, Any], 
                                           classification_counts: Dict[str, int]) -> List[str]:
        """Generate recommendations based on enhancement performance"""
        
        recommendations = []
        
        # Model performance recommendations
        if stats["organic_agreement_rate"] < 0.7:
            recommendations.append("Low ML-organic agreement - consider model retraining with updated ground truth")
        
        if stats["false_positive_filter_rate"] > 0.4:
            recommendations.append("High false positive rate detected - review filtering thresholds and patterns")
        
        if not stats["models_initialized"]:
            recommendations.append("ML models not initialized - run model calibration to enable full ML enhancement")
        
        # Classification recommendations
        uncertain_rate = classification_counts.get("uncertain", 0) / sum(classification_counts.values()) if classification_counts else 0
        if uncertain_rate > 0.3:
            recommendations.append("High uncertainty rate - increase training data and improve feature engineering")
        
        if stats["confidence_improvement_rate"] < 0.5:
            recommendations.append("Low confidence improvement - optimize confidence scoring and threshold tuning")
        
        recommendations.append("Regular model retraining recommended with new vulnerability data")
        
        return recommendations

def create_ml_enhanced_classifier() -> MLEnhancedClassifier:
    """Factory function to create and initialize ML-enhanced classifier"""
    
    classifier = MLEnhancedClassifier()
    
    # Try to initialize with existing models
    if classifier.initialize():
        logger.info("ML-enhanced classifier initialized successfully")
    else:
        logger.warning("ML models not available - using organic classification only")
    
    return classifier

# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Create classifier
    classifier = create_ml_enhanced_classifier()
    
    # Test with sample vulnerability
    sample_vuln = {
        "id": "TEST-001",
        "title": "❌ advanced_vulnerability_detection",
        "description": "Plugin execution failed: name 'logger' is not defined",
        "severity": "Medium",
        "category": "general_security",
        "confidence": 0.0
    }
    
    # Enhance vulnerability
    enhanced_vulns = classifier.enhance_vulnerability_detection([sample_vuln])
    
    if enhanced_vulns:
        enhanced = enhanced_vulns[0]
        print(f"\n🤖 ML ENHANCEMENT RESULTS")
        print(f"Original: {sample_vuln['title']}")
        print(f"ML Classification: {enhanced.final_classification.value}")
        print(f"Confidence: {enhanced.confidence_score:.3f}")
        print(f"Recommendation: {enhanced.recommendation}")
        print(f"ML-Organic Agreement: {enhanced.ml_prediction.organic_agreement}")
    
    # Print statistics
    stats = classifier.get_enhancement_statistics()
    print(f"\n📊 ENHANCEMENT STATISTICS")
    for key, value in stats.items():
        print(f"  {key}: {value}") 