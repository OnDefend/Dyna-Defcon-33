"""
Zero-Day Detection System for AODS Phase 2
Anomaly-based detection for unknown vulnerability patterns
"""

import numpy as np
import logging
import joblib
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

@dataclass
class AnomalyDetectionResult:
    """Result of anomaly detection analysis."""
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    detected_patterns: List[str]
    risk_level: str
    explanation: str
    detection_method: str

class ZeroDayDetectionSystem:
    """Advanced anomaly detection system for zero-day vulnerabilities."""
    
    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or Path(".")
        self.models_dir = self.base_dir / "models" / "zero_day_detection"
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Anomaly detection models
        self.isolation_forest = None
        self.one_class_svm = None
        self.feature_scaler = None
        self.text_vectorizer = None
        self.pca_reducer = None
        
        # Detection statistics
        self.detection_stats = {
            "total_analyzed": 0,
            "anomalies_detected": 0,
            "false_positives": 0,
            "true_positives": 0,
            "detection_rate": 0.0
        }
        
        # Known vulnerability patterns for baseline
        self.known_patterns = self._load_known_patterns()
        
    def _load_known_patterns(self) -> Dict[str, List[str]]:
        """Load known vulnerability patterns for baseline comparison."""
        return {
            "injection_patterns": [
                "sql injection", "command injection", "ldap injection",
                "xpath injection", "nosql injection", "os command injection"
            ],
            "xss_patterns": [
                "cross-site scripting", "reflected xss", "stored xss",
                "dom-based xss", "script injection", "html injection"
            ],
            "crypto_patterns": [
                "weak encryption", "hardcoded key", "insecure random",
                "deprecated crypto", "weak hash", "broken crypto"
            ],
            "access_patterns": [
                "path traversal", "directory traversal", "file inclusion",
                "unauthorized access", "privilege escalation", "authentication bypass"
            ],
            "memory_patterns": [
                "buffer overflow", "heap overflow", "stack overflow",
                "use after free", "null pointer", "memory leak"
            ]
        }
    
    def train_anomaly_detection_models(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train anomaly detection models on baseline vulnerability data."""
        logger.info("🧠 Training Zero-Day Detection Models")
        
        start_time = time.time()
        
        # Prepare training features
        features, text_features = self._extract_features(training_data)
        
        if len(features) < 10:
            logger.warning("Insufficient training data for robust anomaly detection")
            return {"status": "insufficient_data", "samples": len(features)}
        
        # Train text vectorizer
        logger.info("📝 Training text feature vectorizer...")
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 3),
            min_df=2
        )
        
        text_vectors = self.text_vectorizer.fit_transform(text_features).toarray()
        
        # Combine numerical and text features
        if len(features[0]) > 0:
            combined_features = np.hstack([features, text_vectors])
        else:
            combined_features = text_vectors
        
        # Scale features
        logger.info("📊 Scaling features...")
        self.feature_scaler = StandardScaler()
        scaled_features = self.feature_scaler.fit_transform(combined_features)
        
        # Reduce dimensionality for efficiency
        logger.info("🔄 Reducing feature dimensionality...")
        self.pca_reducer = PCA(n_components=min(50, scaled_features.shape[1]))
        reduced_features = self.pca_reducer.fit_transform(scaled_features)
        
        # Train Isolation Forest
        logger.info("🌲 Training Isolation Forest...")
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            bootstrap=False
        )
        self.isolation_forest.fit(reduced_features)
        
        # Train One-Class SVM
        logger.info("🔍 Training One-Class SVM...")
        self.one_class_svm = OneClassSVM(
            kernel='rbf',
            gamma='scale',
            nu=0.1
        )
        self.one_class_svm.fit(reduced_features)
        
        # Save trained models
        self._save_models()
        
        training_time = time.time() - start_time
        
        training_results = {
            "status": "completed",
            "training_time": training_time,
            "training_samples": len(features),
            "feature_dimensions": combined_features.shape[1],
            "reduced_dimensions": reduced_features.shape[1],
            "models_trained": ["isolation_forest", "one_class_svm"],
            "model_files": [
                str(self.models_dir / "isolation_forest.pkl"),
                str(self.models_dir / "one_class_svm.pkl"),
                str(self.models_dir / "feature_scaler.pkl"),
                str(self.models_dir / "text_vectorizer.pkl"),
                str(self.models_dir / "pca_reducer.pkl")
            ]
        }
        
        logger.info(f"✅ Zero-day detection models trained in {training_time:.2f}s")
        logger.info(f"📊 Training samples: {len(features):,}")
        logger.info(f"🎯 Feature dimensions: {combined_features.shape[1]} → {reduced_features.shape[1]}")
        
        return training_results
    
    def _extract_features(self, data: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[str]]:
        """Extract numerical and text features from vulnerability data."""
        numerical_features = []
        text_features = []
        
        for item in data:
            # Numerical features
            num_features = [
                len(item.get('code_snippet', '')),
                len(item.get('description', '')),
                item.get('line_number', 0),
                len(item.get('function_name', '')),
                item.get('confidence_score', 0.5),
                # Additional heuristic features
                item.get('code_snippet', '').count('('),
                item.get('code_snippet', '').count('{'),
                item.get('code_snippet', '').count('='),
                item.get('code_snippet', '').count(';')
            ]
            numerical_features.append(num_features)
            
            # Text features
            text_content = f"{item.get('description', '')} {item.get('code_snippet', '')} {item.get('vulnerability_type', '')}"
            text_features.append(text_content)
        
        return np.array(numerical_features), text_features
    
    def _save_models(self):
        """Save trained models to disk."""
        model_files = {
            'isolation_forest.pkl': self.isolation_forest,
            'one_class_svm.pkl': self.one_class_svm,
            'feature_scaler.pkl': self.feature_scaler,
            'text_vectorizer.pkl': self.text_vectorizer,
            'pca_reducer.pkl': self.pca_reducer
        }
        
        for filename, model in model_files.items():
            if model is not None:
                joblib.dump(model, self.models_dir / filename)
                logger.debug(f"Saved model: {filename}")
    
    def load_models(self) -> bool:
        """Load trained models from disk."""
        try:
            model_files = [
                'isolation_forest.pkl',
                'one_class_svm.pkl', 
                'feature_scaler.pkl',
                'text_vectorizer.pkl',
                'pca_reducer.pkl'
            ]
            
            for filename in model_files:
                filepath = self.models_dir / filename
                if not filepath.exists():
                    logger.warning(f"Model file not found: {filename}")
                    return False
            
            self.isolation_forest = joblib.load(self.models_dir / 'isolation_forest.pkl')
            self.one_class_svm = joblib.load(self.models_dir / 'one_class_svm.pkl')
            self.feature_scaler = joblib.load(self.models_dir / 'feature_scaler.pkl')
            self.text_vectorizer = joblib.load(self.models_dir / 'text_vectorizer.pkl')
            self.pca_reducer = joblib.load(self.models_dir / 'pca_reducer.pkl')
            
            logger.info("✅ Zero-day detection models loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False
    
    def detect_zero_day_vulnerability(self, sample: Dict[str, Any]) -> AnomalyDetectionResult:
        """Detect potential zero-day vulnerability using anomaly detection."""
        
        if not self._models_ready():
            return AnomalyDetectionResult(
                is_anomaly=False,
                anomaly_score=0.0,
                confidence=0.0,
                detected_patterns=[],
                risk_level="unknown",
                explanation="Zero-day detection models not available",
                detection_method="none"
            )
        
        # Extract features for the sample
        features, text_features = self._extract_features([sample])
        
        # Transform features using trained pipeline
        text_vectors = self.text_vectorizer.transform(text_features).toarray()
        
        if len(features[0]) > 0:
            combined_features = np.hstack([features, text_vectors])
        else:
            combined_features = text_vectors
        
        scaled_features = self.feature_scaler.transform(combined_features)
        reduced_features = self.pca_reducer.transform(scaled_features)
        
        # Get predictions from both models
        isolation_prediction = self.isolation_forest.predict(reduced_features)[0]
        isolation_score = self.isolation_forest.decision_function(reduced_features)[0]
        
        svm_prediction = self.one_class_svm.predict(reduced_features)[0]
        svm_score = self.one_class_svm.decision_function(reduced_features)[0]
        
        # Combine results
        is_anomaly_isolation = isolation_prediction == -1
        is_anomaly_svm = svm_prediction == -1
        
        # Consensus-based anomaly detection
        is_anomaly = is_anomaly_isolation or is_anomaly_svm
        
        # Calculate combined anomaly score
        combined_score = (abs(isolation_score) + abs(svm_score)) / 2
        
        # Determine confidence based on agreement
        if is_anomaly_isolation and is_anomaly_svm:
            confidence = 0.9  # High confidence when both agree
            detection_method = "consensus"
        elif is_anomaly_isolation or is_anomaly_svm:
            confidence = 0.7  # Medium confidence when one detects
            detection_method = "isolation_forest" if is_anomaly_isolation else "one_class_svm"
        else:
            confidence = 0.1  # Low confidence when neither detects
            detection_method = "none"
        
        # Analyze detected patterns
        detected_patterns = self._analyze_anomaly_patterns(sample, combined_score)
        
        # Determine risk level
        risk_level = self._determine_risk_level(combined_score, confidence)
        
        # Generate explanation
        explanation = self._generate_explanation(
            sample, is_anomaly, combined_score, detected_patterns, detection_method
        )
        
        # Update statistics
        self.detection_stats["total_analyzed"] += 1
        if is_anomaly:
            self.detection_stats["anomalies_detected"] += 1
        
        result = AnomalyDetectionResult(
            is_anomaly=is_anomaly,
            anomaly_score=combined_score,
            confidence=confidence,
            detected_patterns=detected_patterns,
            risk_level=risk_level,
            explanation=explanation,
            detection_method=detection_method
        )
        
        logger.debug(f"Zero-day detection: {'ANOMALY' if is_anomaly else 'NORMAL'} "
                    f"(score: {combined_score:.3f}, confidence: {confidence:.3f})")
        
        return result
    
    def _models_ready(self) -> bool:
        """Check if all models are loaded and ready."""
        return all([
            self.isolation_forest is not None,
            self.one_class_svm is not None,
            self.feature_scaler is not None,
            self.text_vectorizer is not None,
            self.pca_reducer is not None
        ])
    
    def _analyze_anomaly_patterns(self, sample: Dict[str, Any], score: float) -> List[str]:
        """Analyze what patterns make this sample anomalous."""
        patterns = []
        
        code_snippet = sample.get('code_snippet', '').lower()
        description = sample.get('description', '').lower()
        
        # Check for novel code patterns
        if score > 0.5:
            if 'function' in code_snippet and 'unusual' in description:
                patterns.append("novel_function_pattern")
            
            if len(code_snippet) > 1000:
                patterns.append("unusually_long_code")
            
            if code_snippet.count('(') > 10:
                patterns.append("complex_function_calls")
        
        # Check for unknown vulnerability types
        vuln_type = sample.get('vulnerability_type', '').lower()
        is_known = False
        for category, known_types in self.known_patterns.items():
            if any(known_type in vuln_type for known_type in known_types):
                is_known = True
                break
        
        if not is_known and score > 0.3:
            patterns.append("unknown_vulnerability_type")
        
        # Check for unusual metadata combinations
        if sample.get('severity') == 'critical' and sample.get('confidence_score', 0) < 0.3:
            patterns.append("severity_confidence_mismatch")
        
        return patterns
    
    def _determine_risk_level(self, score: float, confidence: float) -> str:
        """Determine risk level based on anomaly score and confidence."""
        risk_score = score * confidence
        
        if risk_score > 0.8:
            return "critical"
        elif risk_score > 0.6:
            return "high"
        elif risk_score > 0.4:
            return "medium"
        else:
            return "low"
    
    def _generate_explanation(self, sample: Dict[str, Any], is_anomaly: bool,
                            score: float, patterns: List[str], method: str) -> str:
        """Generate human-readable explanation for the detection result."""
        
        if not is_anomaly:
            return f"Sample appears normal (anomaly score: {score:.3f}). " \
                   f"Patterns match known vulnerability types."
        
        explanation_parts = [
            f"Potential zero-day vulnerability detected (anomaly score: {score:.3f})"
        ]
        
        if patterns:
            explanation_parts.append(f"Detected patterns: {', '.join(patterns)}")
        
        explanation_parts.append(f"Detection method: {method}")
        
        if score > 0.7:
            explanation_parts.append("High anomaly score suggests novel vulnerability pattern")
        elif score > 0.5:
            explanation_parts.append("Medium anomaly score indicates unusual characteristics")
        
        return ". ".join(explanation_parts) + "."
    
    def batch_zero_day_detection(self, samples: List[Dict[str, Any]]) -> List[AnomalyDetectionResult]:
        """Perform zero-day detection on a batch of samples."""
        logger.info(f"🔍 Running zero-day detection on {len(samples)} samples")
        
        results = []
        start_time = time.time()
        
        for i, sample in enumerate(samples):
            if i % 100 == 0 and i > 0:
                logger.info(f"Processed {i}/{len(samples)} samples")
            
            result = self.detect_zero_day_vulnerability(sample)
            results.append(result)
        
        processing_time = time.time() - start_time
        anomaly_count = sum(1 for r in results if r.is_anomaly)
        
        logger.info(f"✅ Batch detection completed in {processing_time:.2f}s")
        logger.info(f"📊 Anomalies detected: {anomaly_count}/{len(samples)} ({anomaly_count/len(samples):.1%})")
        
        return results
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get comprehensive detection statistics."""
        total = self.detection_stats["total_analyzed"]
        anomalies = self.detection_stats["anomalies_detected"]
        
        return {
            **self.detection_stats,
            "detection_rate": anomalies / max(total, 1),
            "models_ready": self._models_ready(),
            "model_files_exist": all(
                (self.models_dir / f).exists() 
                for f in ['isolation_forest.pkl', 'one_class_svm.pkl']
            )
        }

# Global zero-day detection system
zero_day_detector = ZeroDayDetectionSystem()

def detect_zero_day_vulnerabilities(samples: List[Dict[str, Any]]) -> List[AnomalyDetectionResult]:
    """Global function for zero-day vulnerability detection."""
    if not zero_day_detector.load_models():
        logger.warning("Zero-day detection models not available, training with provided samples")
        
        # Use first 80% for training, last 20% for detection
        split_point = int(len(samples) * 0.8)
        training_samples = samples[:split_point]
        detection_samples = samples[split_point:]
        
        if len(training_samples) >= 10:
            zero_day_detector.train_anomaly_detection_models(training_samples)
            return zero_day_detector.batch_zero_day_detection(detection_samples)
        else:
            logger.error("Insufficient samples for zero-day detection training")
            return []
    
    return zero_day_detector.batch_zero_day_detection(samples) 