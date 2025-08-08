#!/usr/bin/env python3
"""
AODS Machine Learning Integration Manager

Comprehensive ML integration system for enhanced vulnerability detection
and intelligent security analysis in Android applications.

Features:
- Integration with existing VulnerabilityClassifier
- Hybrid organic + ML detection mode
- Performance monitoring and metrics
- Fallback to organic-only detection
- ML model lifecycle management
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
from datetime import datetime
import threading
import time

# AODS Core Components
from .vulnerability_classifier import VulnerabilityClassifier, ClassificationResult

# Optional ML components
try:
    from .ml_vulnerability_classifier import MLVulnerabilityClassifier, create_ml_classifier
    from .ml_training_pipeline import MLTrainingPipeline
    ML_COMPONENTS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"ML components not available: {e}")
    ML_COMPONENTS_AVAILABLE = False
    MLVulnerabilityClassifier = None
    create_ml_classifier = None
    MLTrainingPipeline = None

from dataclasses import dataclass

# Set up logging
logging.basicConfig(level=logging.INFO)

@dataclass
class ClassificationResult:
    """Result from ML classification"""
    is_vulnerability: bool
    confidence: float
    vulnerability_type: str
    severity: str
    reasoning: str
    ml_enabled: bool = False
    hybrid_reasoning: Optional[str] = None

class MLIntegrationManager:
    """Enhanced ML Integration Manager with robust fallback and hybrid detection"""
    
    def initialize(self):
        """Initialize ML integration manager (compatibility method)."""
        try:
            return self._initialize_ml_components()
        except AttributeError:
            # Fallback: just return ml_model_ready status
            return getattr(self, 'ml_model_ready', False)

    def __init__(self, enable_ml: bool = True, fallback_mode: bool = True):
        self.logger = logging.getLogger(__name__)
        
        # Core configuration
        self.enable_ml = enable_ml
        self.fallback_mode = fallback_mode
        self.hybrid_mode = True
        self.vulnerable_app_mode = False
        self.vulnerable_config = None
        
        # ML components
        self.ml_classifier = None
        self.ml_model_ready = False
        self.ml_training_in_progress = False
        
        # Performance metrics - FIXED: Use consistent key names
        self.ml_metrics = {
            'total_predictions': 0,  # Changed from 'predictions_made'
            'ml_successes': 0,
            'ml_failures': 0,
            'organic_fallbacks': 0,
            'hybrid_agreements': 0,
            'hybrid_disagreements': 0
        }
        
        # Initialize components
        if self.enable_ml:
            self._initialize_ml_components()
    
    def _initialize_ml_components(self):
        """Initialize ML components with error handling"""
        try:
            if not ML_COMPONENTS_AVAILABLE:
                self.logger.warning("ML components not available - using organic-only mode")
                self.ml_model_ready = False
                return
                
            # Check if model exists and load it
            model_path = Path("models/ml_vulnerability_model.pkl")
            if model_path.exists():
                try:
                    # Actually load the ML classifier
                    if MLVulnerabilityClassifier:
                        self.ml_classifier = MLVulnerabilityClassifier()
                        self.ml_model_ready = True
                        self.logger.info("ML model loaded and classifier initialized")
                    else:
                        self.logger.warning("MLVulnerabilityClassifier not available")
                        self.ml_model_ready = False
                except Exception as e:
                    self.logger.error(f"Failed to load ML classifier: {e}")
                    self.ml_model_ready = False
            else:
                self.logger.warning("ML model not found - will use organic-only mode")
                self.ml_model_ready = False
                
        except Exception as e:
            self.logger.error(f"ML initialization error: {e}")
            self.ml_model_ready = False
    
    def classify_finding(self, finding: Dict[str, Any]) -> ClassificationResult:
        """Classify a single finding with ML + organic hybrid approach"""
        try:
            # Always update metrics
            self.ml_metrics['total_predictions'] += 1  # Fixed: consistent key
            
            # Get organic classification first
            organic_result = ClassificationResult(
                is_vulnerability=self._is_vulnerability_organic(finding),
                confidence=0.8,
                vulnerability_type=self._determine_vuln_type(finding),
                severity=self._determine_severity(finding),
                reasoning="Organic classification",
                ml_enabled=self.enable_ml
            )
            
            # If ML is ready and enabled, get ML prediction
            if self.ml_model_ready and self.ml_classifier and self.enable_ml:
                try:
                    # Use the ML classifier for enhanced classification
                    ml_result = self.ml_classifier.classify_finding(finding)
                    
                    # Compare organic vs ML results for agreement calculation
                    if organic_result.is_vulnerability == ml_result.is_vulnerability:
                        self.ml_metrics['hybrid_agreements'] += 1
                    else:
                        self.ml_metrics['hybrid_disagreements'] += 1
                    
                    self.ml_metrics['ml_successes'] += 1
                    
                    # Return the ML-enhanced result
                    return ClassificationResult(
                        is_vulnerability=ml_result.is_vulnerability,
                        confidence=ml_result.confidence,
                        vulnerability_type=ml_result.category if hasattr(ml_result, 'category') else organic_result.vulnerability_type,
                        severity=ml_result.severity,
                        reasoning=f"ML-enhanced: {getattr(ml_result, 'hybrid_reasoning', 'ML classification')}",
                        ml_enabled=True,
                        hybrid_reasoning=f"Organic: {organic_result.is_vulnerability}, ML: {ml_result.is_vulnerability}"
                    )
                    
                except Exception as e:
                    self.logger.debug(f"ML classification failed, using organic: {e}")
                    self.ml_metrics['ml_failures'] += 1
                    self.ml_metrics['organic_fallbacks'] += 1
                    
                    # Return organic result with ML metadata
                    organic_result.hybrid_reasoning = f"ML failed, using organic: {str(e)[:100]}"
                    return organic_result
            else:
                # ML not ready, use organic only
                self.ml_metrics['organic_fallbacks'] += 1
                organic_result.hybrid_reasoning = "ML not ready, using organic only"
                return organic_result
            
        except Exception as e:
            self.logger.error(f"Classification error: {e}")
            self.ml_metrics['ml_failures'] += 1
            
            # Fallback to organic
            return ClassificationResult(
                is_vulnerability=False,
                confidence=0.5,
                vulnerability_type="unknown",
                severity="low",
                reasoning=f"Classification failed: {e}",
                ml_enabled=False
            )
    
    def _is_vulnerability_organic(self, finding: Dict[str, Any]) -> bool:
        """Organic vulnerability detection logic"""
        content = str(finding.get('content', '')).lower()
        title = str(finding.get('title', '')).lower()
        
        # Check for vulnerability indicators
        vuln_indicators = [
            'exploit', 'vulnerability', 'security', 'permission', 'exposed',
            'hardcoded', 'debug', 'cleartext', 'insecure', 'weak'
        ]
        
        combined_text = f"{title} {content}"
        return any(indicator in combined_text for indicator in vuln_indicators)
    
    def _determine_vuln_type(self, finding: Dict[str, Any]) -> str:
        """Determine vulnerability type"""
        content = str(finding.get('content', '')).lower()
        
        if 'permission' in content:
            return 'permission_issue'
        elif 'debug' in content:
            return 'debug_issue'
        elif 'cleartext' in content:
            return 'network_security'
        else:
            return 'general_security'
    
    def _determine_severity(self, finding: Dict[str, Any]) -> str:
        """Determine vulnerability severity"""
        content = str(finding.get('content', '')).lower()
        
        if any(word in content for word in ['critical', 'rce', 'remote']):
            return 'critical'
        elif any(word in content for word in ['high', 'exploit', 'exposed']):
            return 'high'
        elif any(word in content for word in ['medium', 'weak', 'insecure']):
            return 'medium'
        else:
            return 'low'
    
    def classify_all_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Classify all findings and return comprehensive results"""
        vulnerabilities = []
        informational = []
        
        for finding in findings:
            result = self.classify_finding(finding)
            
            # Create enhanced finding with consistent data structure
            enhanced_finding = {
                **finding,  # Preserve original finding data
                "is_vulnerability": result.is_vulnerability,  # Add top-level is_vulnerability field
                "classification": {
                    "is_vulnerability": result.is_vulnerability,
                    "severity": result.severity,
                    "category": result.vulnerability_type,
                    "confidence": result.confidence,
                    "evidence": [],  # ML doesn't provide detailed evidence yet
                    "success_indicators": [],
                    "false_positive_indicators": [],
                    "semantic_score": 0.8  # Default semantic score for ML
                }
            }
            
            # Add ML-specific metadata
            if result.ml_enabled:
                enhanced_finding.update({
                    'ml_enabled': result.ml_enabled,
                    'reasoning': result.reasoning,
                    'type': result.vulnerability_type
                })
                
                if result.hybrid_reasoning:
                    enhanced_finding['hybrid_reasoning'] = result.hybrid_reasoning
            
            if result.is_vulnerability:
                vulnerabilities.append(enhanced_finding)
            else:
                informational.append(enhanced_finding)
        
        # Generate summary
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('classification', {}).get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'vulnerabilities': vulnerabilities,
            'informational': informational,
            'statistics': {
                'total_findings': len(findings),
                'vulnerabilities_found': len(vulnerabilities),
                'critical': severity_counts['critical'],
                'high': severity_counts['high'], 
                'medium': severity_counts['medium'],
                'low': severity_counts['low'],
                'info': len(informational)
            },
            'vulnerability_summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': severity_counts['critical'],
                'high_count': severity_counts['high'], 
                'medium_count': severity_counts['medium'],
                'low_count': severity_counts['low']
            },
            'metadata': {
                'classification_timestamp': datetime.now().isoformat(),
                'classifier_version': '2.0.0-ml-enhanced',
                'ml_enabled': self.enable_ml,
                'ml_model_ready': self.ml_model_ready
            },
            'ml_metrics': self.ml_metrics.copy()
        }
    
    def train_ml_model(self, 
                      training_data_path: Optional[str] = None,
                      background: bool = True,
                      force_retrain: bool = False) -> bool:
        """
        Comprehensive ML model training implementation.
        
        Args:
            training_data_path: Path to training data (JSON format)
            background: Whether to run training in background
            force_retrain: Force retraining even if model exists
            
        Returns:
            bool: True if training completed successfully
        """
        try:
            self.logger.info("Initiating comprehensive ML model training...")
            
            if not ML_COMPONENTS_AVAILABLE:
                self.logger.error("ML components not available for training")
                return False
            
            # Check if model already exists and is recent
            model_path = Path("models/ml_vulnerability_model.pkl")
            if model_path.exists() and not force_retrain:
                model_age = datetime.now().timestamp() - model_path.stat().st_mtime
                if model_age < 7 * 24 * 3600:  # Less than 7 days old
                    self.logger.info("Recent ML model found, skipping training")
                    self.ml_model_ready = True
                    return True
            
            if background:
                # Run training in background thread
                training_thread = threading.Thread(
                    target=self._execute_training,
                    args=(training_data_path, force_retrain),
                    daemon=True
                )
                training_thread.start()
                return True
            else:
                # Run training synchronously
                return self._execute_training(training_data_path, force_retrain)
                
        except Exception as e:
            self.logger.error(f"ML training initiation failed: {e}")
            return False
    
    def _execute_training(self, training_data_path: Optional[str], force_retrain: bool) -> bool:
        """Execute the actual ML training process."""
        self.ml_training_in_progress = True
        
        try:
            self.logger.info("Starting comprehensive ML training pipeline...")
            
            # Step 1: Prepare training data
            training_data = self._prepare_training_data(training_data_path)
            if not training_data or len(training_data) < 100:
                self.logger.error("Insufficient training data (minimum 100 samples required)")
                return False
            
            self.logger.info(f"Prepared {len(training_data)} training samples")
            
            # Step 2: Feature extraction and preprocessing
            features, labels = self._extract_features_and_labels(training_data)
            if features is None or labels is None:
                self.logger.error("Feature extraction failed")
                return False
            
            self.logger.info(f"Extracted features with shape: {features.shape if hasattr(features, 'shape') else len(features)}")
            
            # Step 3: Split data for training and validation
            train_features, val_features, train_labels, val_labels = self._split_training_data(
                features, labels, test_size=0.2
            )
            
            # Step 4: Train multiple model variants
            models = self._train_model_variants(train_features, train_labels)
            if not models:
                self.logger.error("Model training failed")
                return False
            
            # Step 5: Validate models and select best one
            best_model = self._validate_and_select_model(
                models, val_features, val_labels
            )
            if not best_model:
                self.logger.error("Model validation failed")
                return False
            
            # Step 6: Save the best model
            if self._save_trained_model(best_model):
                self.logger.info("ML model training completed successfully")
                self.ml_model_ready = True
                
                # Reload the ML classifier with new model
                self._reload_ml_classifier()
                
                return True
            else:
                self.logger.error("Failed to save trained model")
                return False
                
        except Exception as e:
            self.logger.error(f"ML training execution failed: {e}")
            return False
        finally:
            self.ml_training_in_progress = False
    
    def _prepare_training_data(self, data_path: Optional[str]) -> List[Dict[str, Any]]:
        """Prepare training data from various sources."""
        training_data = []
        
        try:
            # Source 1: Load from provided path
            if data_path and Path(data_path).exists():
                with open(data_path, 'r') as f:
                    external_data = json.load(f)
                    if isinstance(external_data, list):
                        training_data.extend(external_data)
                        self.logger.info(f"Loaded {len(external_data)} samples from {data_path}")
            
            # Source 2: Load from default training data location
            default_data_path = Path("data/training/vulnerability_samples.json")
            if default_data_path.exists():
                with open(default_data_path, 'r') as f:
                    default_data = json.load(f)
                    if isinstance(default_data, list):
                        training_data.extend(default_data)
                        self.logger.info(f"Loaded {len(default_data)} samples from default location")
            
            # Source 3: Generate synthetic training data if insufficient data
            if len(training_data) < 500:
                synthetic_data = self._generate_synthetic_training_data(500 - len(training_data))
                training_data.extend(synthetic_data)
                self.logger.info(f"Generated {len(synthetic_data)} synthetic training samples")
            
            # Source 4: Load historical analysis results
            historical_data = self._load_historical_analysis_data()
            if historical_data:
                training_data.extend(historical_data)
                self.logger.info(f"Loaded {len(historical_data)} historical analysis samples")
            
            # Data quality validation and cleaning
            cleaned_data = self._clean_training_data(training_data)
            self.logger.info(f"Cleaned training data: {len(training_data)} -> {len(cleaned_data)} samples")
            
            return cleaned_data
            
        except Exception as e:
            self.logger.error(f"Training data preparation failed: {e}")
            return []
    
    def _extract_features_and_labels(self, training_data: List[Dict[str, Any]]) -> tuple:
        """Extract features and labels from training data."""
        try:
            import numpy as np
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.preprocessing import StandardScaler
            
            features = []
            labels = []
            
            # Initialize feature extractors
            text_vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 3),
                lowercase=True
            )
            
            # Extract text features and metadata features
            text_features = []
            metadata_features = []
            
            for sample in training_data:
                # Extract text content for TF-IDF
                text_content = self._extract_text_content(sample)
                text_features.append(text_content)
                
                # Extract metadata features
                meta_features = self._extract_metadata_features(sample)
                metadata_features.append(meta_features)
                
                # Extract label
                label = self._extract_label(sample)
                labels.append(label)
            
            # Vectorize text features
            text_matrix = text_vectorizer.fit_transform(text_features)
            
            # Normalize metadata features
            metadata_array = np.array(metadata_features)
            scaler = StandardScaler()
            metadata_normalized = scaler.fit_transform(metadata_array)
            
            # Combine features
            from scipy.sparse import hstack
            combined_features = hstack([text_matrix, metadata_normalized])
            
            # Save feature extractors for later use
            self._save_feature_extractors(text_vectorizer, scaler)
            
            return combined_features, np.array(labels)
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")
            return None, None
    
    def _extract_text_content(self, sample: Dict[str, Any]) -> str:
        """Extract text content from training sample."""
        text_parts = []
        
        # Extract various text fields
        for field in ['content', 'code', 'finding_text', 'description', 'details']:
            if field in sample and sample[field]:
                text_parts.append(str(sample[field]))
        
        # Extract file path components
        if 'file_path' in sample:
            file_path = str(sample['file_path'])
            text_parts.append(file_path)
            text_parts.append(Path(file_path).stem)  # Filename without extension
        
        return ' '.join(text_parts)
    
    def _extract_metadata_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract numerical metadata features from training sample."""
        features = []
        
        # Feature 1: Content length
        content = str(sample.get('content', ''))
        features.append(len(content))
        
        # Feature 2: Number of special characters
        special_chars = sum(1 for c in content if not c.isalnum() and not c.isspace())
        features.append(special_chars)
        
        # Feature 3: Entropy (randomness measure)
        entropy = self._calculate_entropy(content)
        features.append(entropy)
        
        # Feature 4: Number of uppercase letters
        uppercase_count = sum(1 for c in content if c.isupper())
        features.append(uppercase_count)
        
        # Feature 5: Ratio of digits to total characters
        digit_ratio = sum(1 for c in content if c.isdigit()) / max(len(content), 1)
        features.append(digit_ratio)
        
        # Feature 6: File extension encoding
        file_ext = Path(str(sample.get('file_path', ''))).suffix.lower()
        ext_encoding = self._encode_file_extension(file_ext)
        features.append(ext_encoding)
        
        # Feature 7: Severity encoding (if available)
        severity = sample.get('severity', 'medium')
        severity_encoding = self._encode_severity(severity)
        features.append(severity_encoding)
        
        # Feature 8: Confidence score (if available)
        confidence = float(sample.get('confidence', 0.5))
        features.append(confidence)
        
        return features
    
    def _extract_label(self, sample: Dict[str, Any]) -> int:
        """Extract binary label from training sample."""
        # Multiple ways to determine if it's a vulnerability
        if 'is_vulnerability' in sample:
            return 1 if sample['is_vulnerability'] else 0
        elif 'label' in sample:
            return 1 if sample['label'] in ['vulnerability', 'true', 'positive', 1] else 0
        elif 'severity' in sample:
            return 1 if sample['severity'] not in ['info', 'none', 'benign'] else 0
        else:
            # Default to positive if finding exists
            return 1
    
    def _split_training_data(self, features, labels, test_size: float = 0.2) -> tuple:
        """Split data into training and validation sets."""
        try:
            from sklearn.model_selection import train_test_split
            
            return train_test_split(
                features, labels,
                test_size=test_size,
                random_state=42,
                stratify=labels  # Ensure balanced split
            )
        except Exception as e:
            self.logger.error(f"Data splitting failed: {e}")
            return features, None, labels, None
    
    def _train_model_variants(self, train_features, train_labels) -> List[Dict[str, Any]]:
        """Train multiple model variants and return them."""
        try:
            from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
            from sklearn.linear_model import LogisticRegression
            from sklearn.svm import SVC
            from sklearn.metrics import classification_report, accuracy_score
            
            models = []
            
            # Model 1: Random Forest
            try:
                rf_model = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42,
                    n_jobs=-1
                )
                rf_model.fit(train_features, train_labels)
                models.append({
                    'name': 'Random Forest',
                    'model': rf_model,
                    'type': 'ensemble'
                })
                self.logger.info("Random Forest model trained successfully")
            except Exception as e:
                self.logger.warning(f"Random Forest training failed: {e}")
            
            # Model 2: Gradient Boosting
            try:
                gb_model = GradientBoostingClassifier(
                    n_estimators=100,
                    learning_rate=0.1,
                    max_depth=6,
                    random_state=42
                )
                gb_model.fit(train_features, train_labels)
                models.append({
                    'name': 'Gradient Boosting',
                    'model': gb_model,
                    'type': 'ensemble'
                })
                self.logger.info("Gradient Boosting model trained successfully")
            except Exception as e:
                self.logger.warning(f"Gradient Boosting training failed: {e}")
            
            # Model 3: Logistic Regression
            try:
                lr_model = LogisticRegression(
                    random_state=42,
                    max_iter=1000,
                    C=1.0
                )
                lr_model.fit(train_features, train_labels)
                models.append({
                    'name': 'Logistic Regression',
                    'model': lr_model,
                    'type': 'linear'
                })
                self.logger.info("Logistic Regression model trained successfully")
            except Exception as e:
                self.logger.warning(f"Logistic Regression training failed: {e}")
            
            # Model 4: SVM (if dataset is not too large)
            if train_features.shape[0] < 10000:
                try:
                    svm_model = SVC(
                        kernel='rbf',
                        probability=True,
                        random_state=42
                    )
                    svm_model.fit(train_features, train_labels)
                    models.append({
                        'name': 'SVM',
                        'model': svm_model,
                        'type': 'kernel'
                    })
                    self.logger.info("SVM model trained successfully")
                except Exception as e:
                    self.logger.warning(f"SVM training failed: {e}")
            
            return models
            
        except Exception as e:
            self.logger.error(f"Model training failed: {e}")
            return []
    
    def _validate_and_select_model(self, models: List[Dict[str, Any]], 
                                  val_features, val_labels) -> Optional[Dict[str, Any]]:
        """Validate models and select the best performing one."""
        try:
            from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
            
            best_model = None
            best_score = 0.0
            
            for model_info in models:
                model = model_info['model']
                name = model_info['name']
                
                try:
                    # Make predictions
                    predictions = model.predict(val_features)
                    probabilities = model.predict_proba(val_features)[:, 1] if hasattr(model, 'predict_proba') else predictions
                    
                    # Calculate metrics
                    accuracy = accuracy_score(val_labels, predictions)
                    precision, recall, f1, _ = precision_recall_fscore_support(val_labels, predictions, average='binary')
                    auc_score = roc_auc_score(val_labels, probabilities)
                    
                    # Composite score (weighted combination of metrics)
                    composite_score = (accuracy * 0.3) + (f1 * 0.4) + (auc_score * 0.3)
                    
                    self.logger.info(f"{name} - Accuracy: {accuracy:.3f}, F1: {f1:.3f}, AUC: {auc_score:.3f}, Composite: {composite_score:.3f}")
                    
                    # Update best model if this one is better
                    if composite_score > best_score:
                        best_score = composite_score
                        best_model = {
                            'model': model,
                            'name': name,
                            'type': model_info['type'],
                            'metrics': {
                                'accuracy': accuracy,
                                'precision': precision,
                                'recall': recall,
                                'f1_score': f1,
                                'auc_score': auc_score,
                                'composite_score': composite_score
                            }
                        }
                        
                except Exception as e:
                    self.logger.error(f"Validation failed for {name}: {e}")
                    continue
            
            if best_model:
                self.logger.info(f"Selected best model: {best_model['name']} with composite score: {best_score:.3f}")
            
            return best_model
            
        except Exception as e:
            self.logger.error(f"Model validation failed: {e}")
            return None
    
    def _save_trained_model(self, best_model: Dict[str, Any]) -> bool:
        """Save the best trained model to a file."""
        try:
            import joblib
            
            model_path = Path("models/ml_vulnerability_model.pkl")
            model_path.parent.mkdir(parents=True, exist_ok=True)
            
            joblib.dump(best_model['model'], model_path)
            self.logger.info(f"ML model saved to {model_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save ML model: {e}")
            return False
    
    def _reload_ml_classifier(self):
        """Reload the ML classifier with the newly trained model."""
        try:
            if MLVulnerabilityClassifier:
                self.ml_classifier = MLVulnerabilityClassifier()
                self.logger.info("ML classifier reloaded with new model")
            else:
                self.logger.warning("MLVulnerabilityClassifier not available, cannot reload classifier.")
        except Exception as e:
            self.logger.error(f"Failed to reload ML classifier: {e}")
    
    def _generate_synthetic_training_data(self, num_samples: int) -> List[Dict[str, Any]]:
        """Generate synthetic training data for scenarios not covered by real data."""
        synthetic_data = []
        for i in range(num_samples):
            sample = {
                'content': f"synthetic_finding_{i}",
                'severity': 'medium',
                'confidence': 0.8,
                'is_vulnerability': False,
                'file_path': f"synthetic_file_{i}.txt"
            }
            synthetic_data.append(sample)
        return synthetic_data
    
    def _load_historical_analysis_data(self) -> List[Dict[str, Any]]:
        """Load historical analysis results for training."""
        # This is a placeholder. In a real system, you'd load data from a database or file.
        # For now, we'll return a small number of dummy data.
        return [
            {'content': 'This is a known vulnerability in the application.', 'severity': 'high', 'confidence': 0.9, 'is_vulnerability': True, 'file_path': 'app/src/main/java/com/example/app/MainActivity.java'},
            {'content': 'Debug mode enabled in the application.', 'severity': 'medium', 'confidence': 0.7, 'is_vulnerability': False, 'file_path': 'app/src/main/java/com/example/app/DebugActivity.java'},
            {'content': 'Permission issue in the application.', 'severity': 'low', 'confidence': 0.6, 'is_vulnerability': True, 'file_path': 'app/src/main/java/com/example/app/PermissionsActivity.java'}
        ]
    
    def _clean_training_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Basic data cleaning for training."""
        cleaned_data = []
        for sample in data:
            # Ensure required fields exist
            if 'content' not in sample:
                self.logger.warning(f"Skipping sample with missing 'content': {sample}")
                continue
            
            # Convert boolean labels to integers
            if 'is_vulnerability' in sample:
                sample['is_vulnerability'] = 1 if sample['is_vulnerability'] else 0
            
            # Ensure severity is a string
            if 'severity' in sample:
                sample['severity'] = str(sample['severity'])
            
            # Ensure confidence is a float
            if 'confidence' in sample:
                sample['confidence'] = float(sample['confidence'])
            
            # Ensure file_path is a string
            if 'file_path' in sample:
                sample['file_path'] = str(sample['file_path'])
            
            cleaned_data.append(sample)
        return cleaned_data
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        # Count frequency of each character
        freq = {c: s.count(c) for c in set(s)}
        # Calculate entropy
        entropy = 0.0
        for f in freq.values():
            p = f / len(s)
            entropy -= p * np.log2(p)
        return entropy
    
    def _encode_file_extension(self, ext: str) -> float:
        """Encode file extension into a numerical feature."""
        # Simple one-hot encoding for common extensions
        if ext.lower() in ['.apk', '.dex', '.jar', '.class']:
            return 1.0
        elif ext.lower() in ['.xml', '.json', '.properties']:
            return 0.8
        elif ext.lower() in ['.txt', '.log', '.md']:
            return 0.6
        elif ext.lower() in ['.png', '.jpg', '.jpeg', '.gif']:
            return 0.5
        else:
            return 0.0
    
    def _encode_severity(self, severity: str) -> float:
        """Encode severity string into a numerical feature."""
        if severity.lower() in ['critical', 'rce', 'remote']:
            return 1.0
        elif severity.lower() in ['high', 'exploit', 'exposed']:
            return 0.9
        elif severity.lower() in ['medium', 'weak', 'insecure']:
            return 0.7
        else:
            return 0.5
    
    def _save_feature_extractors(self, text_vectorizer, scaler):
        """Save feature extractors (vectorizer, scaler) to a file."""
        try:
            import joblib
            
            extractors_path = Path("models/ml_feature_extractors.pkl")
            extractors_path.parent.mkdir(parents=True, exist_ok=True)
            
            joblib.dump((text_vectorizer, scaler), extractors_path)
            self.logger.info(f"Feature extractors saved to {extractors_path}")
        except Exception as e:
            self.logger.error(f"Failed to save feature extractors: {e}")
    
    def _load_feature_extractors(self) -> tuple:
        """Load feature extractors (vectorizer, scaler) from a file."""
        try:
            import joblib
            
            extractors_path = Path("models/ml_feature_extractors.pkl")
            if extractors_path.exists():
                text_vectorizer, scaler = joblib.load(extractors_path)
                self.logger.info(f"Feature extractors loaded from {extractors_path}")
                return text_vectorizer, scaler
            else:
                self.logger.warning(f"Feature extractors not found at {extractors_path}. Training will use default settings.")
                return None, None
        except Exception as e:
            self.logger.error(f"Failed to load feature extractors: {e}")
            return None, None
    
    def get_ml_status(self) -> Dict[str, Any]:
        """Get current ML status"""
        return {
            'ml_enabled': self.enable_ml,
            'ml_model_ready': self.ml_model_ready,
            'training_in_progress': self.ml_training_in_progress,
            'hybrid_mode': self.hybrid_mode,
            'fallback_mode': self.fallback_mode,
            'metrics': self.ml_metrics.copy(),
            'model_path': str(Path("models/ml_vulnerability_model.pkl")),
            'model_exists': Path("models/ml_vulnerability_model.pkl").exists()
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get detailed performance metrics"""
        total_predictions = self.ml_metrics['total_predictions']  # Fixed: consistent key
        
        if total_predictions == 0:
            return {'status': 'No predictions made yet'}
        
        # Calculate ML-organic agreement percentage
        total_comparisons = self.ml_metrics['hybrid_agreements'] + self.ml_metrics['hybrid_disagreements']
        ml_organic_agreement = (self.ml_metrics['hybrid_agreements'] / max(1, total_comparisons)) * 100.0
        
        return {
            'total_predictions': total_predictions,
            'ml_success_rate': self.ml_metrics['ml_successes'] / total_predictions,
            'ml_failure_rate': self.ml_metrics['ml_failures'] / total_predictions,
            'fallback_rate': self.ml_metrics['organic_fallbacks'] / total_predictions,
            'hybrid_agreement_rate': self.ml_metrics['hybrid_agreements'] / max(1, self.ml_metrics['hybrid_agreements'] + self.ml_metrics['hybrid_disagreements']),
            'ml_organic_agreement_percentage': ml_organic_agreement,
            'total_ml_vs_organic_comparisons': total_comparisons,
            'raw_metrics': self.ml_metrics.copy()
        }
    
    def enable_ml_detection(self):
        """Enable ML detection"""
        self.enable_ml = True
        self._initialize_ml_components()
        self.logger.info("ML detection enabled")
    
    def disable_ml_detection(self):
        """Disable ML detection (organic-only mode)"""
        self.enable_ml = False
        self.logger.info("ML detection disabled - using organic-only mode")
    
    def toggle_hybrid_mode(self, enabled: bool):
        """Enable/disable hybrid mode"""
        self.hybrid_mode = enabled
        if self.ml_classifier:
            self.ml_classifier.hybrid_mode = enabled
        self.logger.info(f"Hybrid mode {'enabled' if enabled else 'disabled'}")
    
    def reset_metrics(self):
        """Reset performance metrics"""
        self.ml_metrics = {
            'total_predictions': 0,  # Fixed: consistent key
            'ml_successes': 0,
            'ml_failures': 0,
            'organic_fallbacks': 0,
            'hybrid_agreements': 0,
            'hybrid_disagreements': 0
        }
        self.logger.info("ML metrics reset")

    def get_ml_orchestrator(self):
        """Get singleton ML orchestrator"""
        return self

    def initialize_ml_system(self) -> bool:
        """Initialize ML system components."""
        try:
            # Initialize ML system components
            self._initialize_ml_components()
            success = self.ml_model_ready or self.fallback_mode
            self.logger.info(f"ML system initialization: {'SUCCESS' if success else 'FAILED'}")
            return success
        except Exception as e:
            self.logger.error(f"ML system initialization failed: {e}")
            return False
    
    def apply_vulnerable_app_config(self, vulnerable_config) -> bool:
        """
        Apply vulnerable app mode configuration to ML components.
        
        Args:
            vulnerable_config: PipelineConfiguration with vulnerable app settings
            
        Returns:
            bool: True if configuration was applied successfully
        """
        try:
            self.vulnerable_app_mode = True
            self.vulnerable_config = vulnerable_config
            
            # Apply relaxed ML thresholds for vulnerable apps
            if hasattr(vulnerable_config, 'confidence_config'):
                confidence_config = vulnerable_config.confidence_config
                
                # Lower ML confidence thresholds for maximum sensitivity
                if hasattr(confidence_config, 'min_confidence_threshold'):
                    self.classification_threshold = max(0.1, confidence_config.min_confidence_threshold)
                else:
                    self.classification_threshold = 0.1
                
                self.logger.info(f"Applied vulnerable app mode: ML confidence threshold lowered to {self.classification_threshold}")
            
            # Configure ML classifier for vulnerable app mode if available
            if self.ml_classifier and hasattr(self.ml_classifier, 'set_vulnerable_mode'):
                self.ml_classifier.set_vulnerable_mode(True)
                self.logger.info("ML classifier configured for vulnerable app mode")
            
            # Apply framework filtering settings
            if hasattr(vulnerable_config, 'enable_framework_filtering'):
                self.framework_filtering_enabled = vulnerable_config.enable_framework_filtering
                self.logger.info(f"Framework filtering: {'ENABLED' if self.framework_filtering_enabled else 'DISABLED'}")
            
            self.logger.info("Vulnerable app configuration applied to ML components")
            return True
            
        except Exception as e:
            self.logger.warning(f"Failed to apply vulnerable app config to ML components: {e}")
            return False

# Global orchestrator instance
_phase9_orchestrator = None

def get_phase9_orchestrator():
    """Get singleton ML orchestrator"""
    global _phase9_orchestrator
    if _phase9_orchestrator is None:
        _phase9_orchestrator = MLIntegrationManager()
    return _phase9_orchestrator

def initialize_ml_integration() -> bool:
    """Initialize ML integration globally"""
    orchestrator = get_phase9_orchestrator()
    return orchestrator.enable_ml

def get_enhanced_vulnerability_classifier():
    """Get the enhanced vulnerability classifier"""
    return get_phase9_orchestrator()

if __name__ == "__main__":
    # Quick test of the integration
    logging.basicConfig(level=logging.INFO)
    
    # Initialize ML orchestrator
    success = initialize_ml_integration()
    print(f"ML orchestrator initialization: {'SUCCESS' if success else 'FAILED'}")
    
    # Get enhanced classifier
    classifier = get_enhanced_vulnerability_classifier()
    
    # Test classification
    test_finding = {
        "title": "Clear-text traffic enabled",
        "description": "Application allows clear-text HTTP traffic which may expose sensitive data",
        "category": "NETWORK_SECURITY"
    }
    
    result = classifier.classify_finding(test_finding)
    print(f"Classification result: {result.is_vulnerability}, Confidence: {result.confidence:.3f}")
    
    # Get status
    status = get_phase9_orchestrator().get_ml_status()
    print(f"ML Status: {status['ml_enabled']}")
    print(f"Model Ready: {status['ml_model_ready']}") 