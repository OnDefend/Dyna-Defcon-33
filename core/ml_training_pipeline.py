#!/usr/bin/env python3
"""
AODS Machine Learning Training Pipeline

Advanced ML model training system for vulnerability classification and
security analysis enhancement in Android applications.
"""

import logging
import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import random
import pickle

# ML Libraries
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.calibration import CalibratedClassifierCV
import matplotlib.pyplot as plt
import seaborn as sns

# AODS Components
from .ml_vulnerability_classifier import AdaptiveVulnerabilityML, VulnerabilityFeatureExtractor
from .vulnerability_classifier import ClassificationResult

class TrainingDataGenerator:
    """Generate comprehensive training data for ML model"""
    
    def __init__(self, data_dir: str = "data/ml_training"):
        self.logger = logging.getLogger(__name__)
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Training data categories
        self.vulnerability_samples = []
        self.non_vulnerability_samples = []
        
        self.logger.info("TrainingDataGenerator initialized")
    
    def generate_training_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        """Generate comprehensive training dataset"""
        
        self.logger.info("Starting training data generation...")
        
        # 1. Load historical AODS findings
        historical_data = self._load_historical_aods_data()
        self.logger.info(f"Loaded {len(historical_data)} historical samples")
        
        # 2. Generate synthetic samples
        synthetic_data = self._generate_synthetic_samples()
        self.logger.info(f"Generated {len(synthetic_data)} synthetic samples")
        
        # 3. Load external vulnerability datasets
        external_data = self._load_external_datasets()
        self.logger.info(f"Loaded {len(external_data)} external samples")
        
        # 4. Create expert annotations
        expert_data = self._create_expert_annotations()
        self.logger.info(f"Created {len(expert_data)} expert-annotated samples")
        
        # 5. Combine and balance datasets
        combined_data = self._combine_and_balance_datasets([
            historical_data, synthetic_data, external_data, expert_data
        ])
        
        # 6. Extract features and labels
        X, y = self._extract_features_and_labels(combined_data)
        
        self.logger.info(f"Final dataset: {len(X)} samples with {X[0].shape[0] if len(X) > 0 else 0} features")
        self.logger.info(f"Label distribution - Vulnerabilities: {sum(y)}, Non-vulnerabilities: {len(y) - sum(y)}")
        
        return X, y
    
    def _load_historical_aods_data(self) -> List[Dict[str, Any]]:
        """Load historical AODS vulnerability findings for training"""
        historical_samples = []
        
        # Load from recent scan reports (generic approach)
        report_files = []
        
        # Look for any existing security report files in current directory
        for file_path in Path('.').glob('*_security_report.json'):
            report_files.append(str(file_path))
        
        for report_file in report_files:
            report_path = Path(report_file)
            if report_path.exists():
                try:
                    with open(report_path, 'r') as f:
                        report_data = json.load(f)
                    
                    samples = self._extract_samples_from_report(report_data)
                    historical_samples.extend(samples)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to load {report_file}: {e}")
        
        return historical_samples
    
    def _extract_samples_from_report(self, report_data: Dict) -> List[Dict[str, Any]]:
        """Extract training samples from AODS report"""
        samples = []
        
        # Extract vulnerabilities as positive samples
        vulnerabilities = report_data.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            sample = {
                'text': f"{vuln.get('title', '')} {vuln.get('description', '')}",
                'context': {
                    'source_type': vuln.get('type', 'unknown'),
                    'is_production': False,  # Assume test environment
                    'confidence_modifiers': []
                },
                'label': 1,  # Vulnerability
                'severity': vuln.get('severity', 'MEDIUM'),
                'category': vuln.get('category', 'UNKNOWN'),
                'source': 'historical_aods'
            }
            samples.append(sample)
        
        # Extract analysis results as mixed samples
        analysis_results = report_data.get('analysis_results', {})
        for plugin_name, results in analysis_results.items():
            if isinstance(results, list):
                for result in results:
                    # Determine if this is a vulnerability based on content
                    text_content = str(result)
                    is_vulnerability = self._is_vulnerability_content(text_content)
                    
                    sample = {
                        'text': text_content,
                        'context': {
                            'source_type': 'plugin_analysis',
                            'plugin_name': plugin_name,
                            'is_production': False,
                            'confidence_modifiers': []
                        },
                        'label': 1 if is_vulnerability else 0,
                        'severity': 'MEDIUM' if is_vulnerability else 'INFO',
                        'category': plugin_name.upper(),
                        'source': 'historical_aods'
                    }
                    samples.append(sample)
        
        return samples
    
    def _is_vulnerability_content(self, text: str) -> bool:
        """Determine if content represents a vulnerability"""
        text_lower = text.lower()
        
        # Positive indicators
        vuln_indicators = [
            'fail', 'failed', 'failure', 'vulnerable', 'insecure', 'weak',
            'exposed', 'leak', 'cleartext', 'hardcoded', 'missing', 'disabled'
        ]
        
        # Negative indicators
        safe_indicators = [
            'pass', 'passed', 'success', 'secure', 'protected', 'safe',
            'no vulnerabilities', 'no issues', 'properly configured'
        ]
        
        vuln_score = sum(1 for indicator in vuln_indicators if indicator in text_lower)
        safe_score = sum(1 for indicator in safe_indicators if indicator in text_lower)
        
        return vuln_score > safe_score
    
    def _generate_synthetic_samples(self) -> List[Dict[str, Any]]:
        """Generate synthetic vulnerability samples for training"""
        synthetic_samples = []
        
        # Vulnerability templates
        vuln_templates = [
            {
                'template': 'Application allows {protocol} traffic which may expose {data_type}',
                'category': 'NETWORK_SECURITY',
                'severity': 'MEDIUM',
                'variables': {
                    'protocol': ['clear-text HTTP', 'unencrypted', 'plain-text'],
                    'data_type': ['sensitive data', 'user credentials', 'personal information']
                }
            },
            {
                'template': '{component} is exported without proper {protection} configuration',
                'category': 'PLATFORM_SECURITY',
                'severity': 'HIGH',
                'variables': {
                    'component': ['Activity', 'Service', 'Broadcast Receiver', 'Content Provider'],
                    'protection': ['permission', 'security', 'access control']
                }
            },
            {
                'template': 'Hardcoded {secret_type} detected in {location}',
                'category': 'CRYPTOGRAPHY',
                'severity': 'HIGH',
                'variables': {
                    'secret_type': ['API key', 'password', 'secret token', 'private key'],
                    'location': ['source code', 'configuration file', 'manifest', 'resources']
                }
            },
            {
                'template': 'Weak {crypto_element} implementation using {algorithm}',
                'category': 'CRYPTOGRAPHY',
                'severity': 'MEDIUM',
                'variables': {
                    'crypto_element': ['encryption', 'hashing', 'signing'],
                    'algorithm': ['MD5', 'SHA1', 'DES', 'RC4']
                }
            },
            {
                'template': 'Data stored in {storage_type} without proper {protection_type}',
                'category': 'DATA_STORAGE',
                'severity': 'MEDIUM',
                'variables': {
                    'storage_type': ['external storage', 'shared preferences', 'SQLite database'],
                    'protection_type': ['encryption', 'access control', 'permissions']
                }
            }
        ]
        
        # Generate samples from templates
        for template_data in vuln_templates:
            template = template_data['template']
            variables = template_data['variables']
            
            # Generate multiple variations
            for _ in range(10):  # 10 variations per template
                sample_text = template
                context_vars = {}
                
                for var_name, var_options in variables.items():
                    chosen_value = random.choice(var_options)
                    sample_text = sample_text.replace(f'{{{var_name}}}', chosen_value)
                    context_vars[var_name] = chosen_value
                
                sample = {
                    'text': sample_text,
                    'context': {
                        'source_type': 'synthetic',
                        'template_variables': context_vars,
                        'is_production': random.choice([True, False]),
                        'confidence_modifiers': []
                    },
                    'label': 1,  # All synthetic samples are vulnerabilities
                    'severity': template_data['severity'],
                    'category': template_data['category'],
                    'source': 'synthetic'
                }
                synthetic_samples.append(sample)
        
        # Generate non-vulnerability samples
        safe_templates = [
            'Security analysis completed successfully with no issues found',
            'All security checks passed for this component',
            'Proper security configuration detected',
            'No vulnerabilities identified in this analysis',
            'Security implementation meets best practices',
            'Application properly implements security controls'
        ]
        
        for template in safe_templates:
            for _ in range(5):  # 5 variations per safe template
                sample = {
                    'text': template,
                    'context': {
                        'source_type': 'synthetic',
                        'is_production': random.choice([True, False]),
                        'confidence_modifiers': []
                    },
                    'label': 0,  # Non-vulnerability
                    'severity': 'INFO',
                    'category': 'SECURITY_CHECK',
                    'source': 'synthetic'
                }
                synthetic_samples.append(sample)
        
        return synthetic_samples
    
    def _load_external_datasets(self) -> List[Dict[str, Any]]:
        """Load external vulnerability datasets"""
        external_samples = []
        
        # OWASP MASTG test samples
        mastg_samples = self._create_mastg_samples()
        external_samples.extend(mastg_samples)
        
        # Common vulnerability patterns
        common_vulns = self._create_common_vulnerability_samples()
        external_samples.extend(common_vulns)
        
        return external_samples
    
    def _create_mastg_samples(self) -> List[Dict[str, Any]]:
        """Create samples based on OWASP MASTG test cases"""
        mastg_samples = []
        
        mastg_cases = [
            {
                'text': 'MASTG-PLATFORM-01 test failed: Clear-text traffic is allowed',
                'label': 1,
                'severity': 'HIGH',
                'category': 'MASTG_COMPLIANCE'
            },
            {
                'text': 'MASTG-CRYPTO-01 test failed: Weak encryption algorithm detected',
                'label': 1,
                'severity': 'HIGH',
                'category': 'MASTG_COMPLIANCE'
            },
            {
                'text': 'MASTG-AUTH-01 test passed: Authentication implementation is secure',
                'label': 0,
                'severity': 'INFO',
                'category': 'MASTG_COMPLIANCE'
            },
            {
                'text': 'MASTG-NETWORK-01 test failed: Certificate pinning not implemented',
                'label': 1,
                'severity': 'MEDIUM',
                'category': 'MASTG_COMPLIANCE'
            },
            {
                'text': 'MASTG-STORAGE-01 test passed: Data encryption properly implemented',
                'label': 0,
                'severity': 'INFO',
                'category': 'MASTG_COMPLIANCE'
            }
        ]
        
        for case in mastg_cases:
            sample = {
                'text': case['text'],
                'context': {
                    'source_type': 'mastg_test',
                    'is_production': False,
                    'confidence_modifiers': ['mastg_framework']
                },
                'label': case['label'],
                'severity': case['severity'],
                'category': case['category'],
                'source': 'mastg'
            }
            mastg_samples.append(sample)
        
        return mastg_samples
    
    def _create_common_vulnerability_samples(self) -> List[Dict[str, Any]]:
        """Create samples for common mobile vulnerabilities"""
        common_samples = []
        
        vulnerability_descriptions = [
            {
                'text': 'SQL injection vulnerability found in database query',
                'label': 1,
                'severity': 'CRITICAL',
                'category': 'INJECTION'
            },
            {
                'text': 'Cross-site scripting (XSS) vulnerability in WebView',
                'label': 1,
                'severity': 'HIGH',
                'category': 'INJECTION'
            },
            {
                'text': 'Insecure direct object reference allows unauthorized access',
                'label': 1,
                'severity': 'HIGH',
                'category': 'AUTHORIZATION'
            },
            {
                'text': 'Secure random number generation properly implemented',
                'label': 0,
                'severity': 'INFO',
                'category': 'CRYPTOGRAPHY'
            },
            {
                'text': 'Input validation successfully prevents malicious input',
                'label': 0,
                'severity': 'INFO',
                'category': 'VALIDATION'
            }
        ]
        
        for desc in vulnerability_descriptions:
            sample = {
                'text': desc['text'],
                'context': {
                    'source_type': 'common_vulnerability',
                    'is_production': True,
                    'confidence_modifiers': []
                },
                'label': desc['label'],
                'severity': desc['severity'],
                'category': desc['category'],
                'source': 'common_vulns'
            }
            common_samples.append(sample)
        
        return common_samples
    
    def _create_expert_annotations(self) -> List[Dict[str, Any]]:
        """Create expert-annotated samples for high-quality training"""
        expert_samples = []
        
        # High-confidence expert annotations
        expert_annotations = [
            {
                'text': 'Command execution failure indicates potential security vulnerability',
                'label': 1,
                'severity': 'HIGH',
                'category': 'COMMAND_EXECUTION',
                'confidence': 0.95
            },
            {
                'text': 'Application analysis completed without security concerns',
                'label': 0,
                'severity': 'INFO',
                'category': 'ANALYSIS_COMPLETE',
                'confidence': 0.90
            },
            {
                'text': 'Certificate validation bypassed in network implementation',
                'label': 1,
                'severity': 'HIGH',
                'category': 'NETWORK_SECURITY',
                'confidence': 0.92
            },
            {
                'text': 'Proper input sanitization prevents injection attacks',
                'label': 0,
                'severity': 'INFO',
                'category': 'INPUT_VALIDATION',
                'confidence': 0.88
            }
        ]
        
        for annotation in expert_annotations:
            sample = {
                'text': annotation['text'],
                'context': {
                    'source_type': 'expert_annotation',
                    'expert_confidence': annotation['confidence'],
                    'is_production': True,
                    'confidence_modifiers': ['expert_validated']
                },
                'label': annotation['label'],
                'severity': annotation['severity'],
                'category': annotation['category'],
                'source': 'expert'
            }
            expert_samples.append(sample)
        
        return expert_samples
    
    def _combine_and_balance_datasets(self, datasets: List[List[Dict]]) -> List[Dict[str, Any]]:
        """Combine datasets and balance classes"""
        combined_data = []
        for dataset in datasets:
            combined_data.extend(dataset)
        
        # Separate by label
        vulnerabilities = [sample for sample in combined_data if sample['label'] == 1]
        non_vulnerabilities = [sample for sample in combined_data if sample['label'] == 0]
        
        self.logger.info(f"Before balancing - Vulnerabilities: {len(vulnerabilities)}, Non-vulnerabilities: {len(non_vulnerabilities)}")
        
        # Balance the dataset (ensure roughly equal representation)
        min_samples = min(len(vulnerabilities), len(non_vulnerabilities))
        max_samples = max(200, min_samples)  # Ensure minimum dataset size
        
        # If we need more samples, generate additional synthetic ones
        if len(vulnerabilities) < max_samples:
            additional_vulns = self._generate_additional_samples(vulnerabilities, max_samples - len(vulnerabilities))
            vulnerabilities.extend(additional_vulns)
        
        if len(non_vulnerabilities) < max_samples:
            additional_non_vulns = self._generate_additional_samples(non_vulnerabilities, max_samples - len(non_vulnerabilities))
            non_vulnerabilities.extend(additional_non_vulns)
        
        # Random sample to balance
        vulnerabilities = random.sample(vulnerabilities, min(max_samples, len(vulnerabilities)))
        non_vulnerabilities = random.sample(non_vulnerabilities, min(max_samples, len(non_vulnerabilities)))
        
        balanced_data = vulnerabilities + non_vulnerabilities
        random.shuffle(balanced_data)
        
        self.logger.info(f"After balancing - Total samples: {len(balanced_data)}")
        
        return balanced_data
    
    def _generate_additional_samples(self, existing_samples: List[Dict], num_needed: int) -> List[Dict]:
        """Generate additional samples by variation of existing ones"""
        additional_samples = []
        
        for _ in range(num_needed):
            base_sample = random.choice(existing_samples)
            
            # Create variation by adding noise or modification
            varied_sample = base_sample.copy()
            varied_sample['text'] = self._add_text_variation(base_sample['text'])
            varied_sample['source'] = 'synthetic_variation'
            
            additional_samples.append(varied_sample)
        
        return additional_samples
    
    def _add_text_variation(self, text: str) -> str:
        """Add slight variation to text for data augmentation"""
        variations = [
            lambda t: t.replace('fail', 'failure'),
            lambda t: t.replace('detected', 'found'),
            lambda t: t.replace('vulnerability', 'security issue'),
            lambda t: t.replace('secure', 'protected'),
            lambda t: t + ' detected in application analysis'
        ]
        
        variation_func = random.choice(variations)
        try:
            return variation_func(text)
        except:
            return text
    
    def _extract_features_and_labels(self, samples: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features and labels from samples with consistent shapes"""
        feature_extractor = VulnerabilityFeatureExtractor()
        
        # First pass: collect all texts to fit TF-IDF properly
        all_texts = [sample['text'] for sample in samples]
        
        # Pre-fit the TF-IDF vectorizer on all texts to ensure consistent feature space
        feature_extractor._extract_tfidf_features(all_texts)
        
        X = []
        y = []
        
        for sample in samples:
            try:
                # Extract features
                feature_vector = feature_extractor.extract_features(
                    sample['text'], 
                    sample['context']
                )
                
                # Ensure consistent shape by checking combined_features is a 1D array
                if feature_vector.combined_features.ndim == 1:
                    X.append(feature_vector.combined_features)
                    y.append(sample['label'])
                else:
                    self.logger.warning(f"Inconsistent feature shape: {feature_vector.combined_features.shape}")
                    continue
                
            except Exception as e:
                self.logger.warning(f"Failed to extract features from sample: {e}")
                continue
        
        # Verify all feature vectors have the same shape
        if X:
            expected_shape = len(X[0])
            consistent_X = []
            consistent_y = []
            
            for i, (features, label) in enumerate(zip(X, y)):
                if len(features) == expected_shape:
                    consistent_X.append(features)
                    consistent_y.append(label)
                else:
                    self.logger.warning(f"Sample {i} has inconsistent feature shape: {len(features)} vs expected {expected_shape}")
            
            X = consistent_X
            y = consistent_y
        
        return np.array(X), np.array(y)

class MLModelTrainer:
    """Train and evaluate the ML vulnerability detection model"""
    
    def __init__(self, model_path: str = "models/ml_vulnerability_model.pkl"):
        self.logger = logging.getLogger(__name__)
        self.model_path = Path(model_path)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.ml_engine = AdaptiveVulnerabilityML(str(self.model_path))
        self.training_history = []
        
        self.logger.info("MLModelTrainer initialized")
    
    def train_model(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train the ML model with comprehensive evaluation"""
        
        self.logger.info(f"Starting model training with {len(X)} samples...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        self.logger.info(f"Training set: {len(X_train)} samples, Test set: {len(X_test)} samples")
        
        # Train ensemble model
        self.ml_engine.ensemble.fit(X_train, y_train)
        
        # Calibrate probabilities
        self.ml_engine.calibrated_classifier = CalibratedClassifierCV(
            self.ml_engine.ensemble, cv=3
        )
        self.ml_engine.calibrated_classifier.fit(X_train, y_train)
        
        # Evaluate model
        training_results = self._evaluate_model(X_train, y_train, X_test, y_test)
        
        # Save model
        self.ml_engine._save_model()
        
        # Update training history
        training_record = {
            'timestamp': datetime.now().isoformat(),
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'results': training_results
        }
        self.training_history.append(training_record)
        
        self.logger.info("Model training completed successfully")
        
        return training_results
    
    def _evaluate_model(self, X_train: np.ndarray, y_train: np.ndarray, 
                       X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Comprehensive model evaluation"""
        
        results = {}
        
        # Cross-validation on training data
        cv_scores = cross_val_score(
            self.ml_engine.calibrated_classifier, X_train, y_train, 
            cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
            scoring='f1'
        )
        results['cross_validation'] = {
            'mean_f1': float(cv_scores.mean()),
            'std_f1': float(cv_scores.std()),
            'scores': cv_scores.tolist()
        }
        
        # Test set evaluation
        y_pred = self.ml_engine.calibrated_classifier.predict(X_test)
        y_pred_proba = self.ml_engine.calibrated_classifier.predict_proba(X_test)[:, 1]
        
        # Classification metrics
        from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
        
        results['test_performance'] = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred)),
            'recall': float(recall_score(y_test, y_pred)),
            'f1_score': float(f1_score(y_test, y_pred)),
            'roc_auc': float(roc_auc_score(y_test, y_pred_proba))
        }
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        results['confusion_matrix'] = cm.tolist()
        
        # Classification report
        class_report = classification_report(y_test, y_pred, output_dict=True)
        results['classification_report'] = class_report
        
        # Individual classifier performance
        results['ensemble_performance'] = {}
        for name, estimator in self.ml_engine.calibrated_classifier.base_estimator.named_estimators_.items():
            estimator_pred = estimator.predict(X_test)
            results['ensemble_performance'][name] = {
                'accuracy': float(accuracy_score(y_test, estimator_pred)),
                'f1_score': float(f1_score(y_test, estimator_pred))
            }
        
        # Log key metrics
        self.logger.info(f"Model Performance - Accuracy: {results['test_performance']['accuracy']:.3f}, "
                        f"Precision: {results['test_performance']['precision']:.3f}, "
                        f"Recall: {results['test_performance']['recall']:.3f}, "
                        f"F1: {results['test_performance']['f1_score']:.3f}")
        
        return results
    
    def create_training_report(self, training_results: Dict[str, Any]) -> str:
        """Create a comprehensive training report"""
        
        report_lines = [
            "=" * 60,
            "AODS ML Model Training Report",
            "=" * 60,
            "",
            f"Training Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Model Path: {self.model_path}",
            "",
            "Cross-Validation Results:",
            f"  Mean F1 Score: {training_results['cross_validation']['mean_f1']:.3f} "
            f"(±{training_results['cross_validation']['std_f1']:.3f})",
            "",
            "Test Set Performance:",
        ]
        
        perf = training_results['test_performance']
        for metric, value in perf.items():
            report_lines.append(f"  {metric.replace('_', ' ').title()}: {value:.3f}")
        
        report_lines.extend([
            "",
            "Ensemble Performance:",
        ])
        
        for classifier, metrics in training_results['ensemble_performance'].items():
            report_lines.append(f"  {classifier.upper()}:")
            for metric, value in metrics.items():
                report_lines.append(f"    {metric.replace('_', ' ').title()}: {value:.3f}")
        
        report_lines.extend([
            "",
            "Confusion Matrix:",
            f"  True Negatives:  {training_results['confusion_matrix'][0][0]}",
            f"  False Positives: {training_results['confusion_matrix'][0][1]}",
            f"  False Negatives: {training_results['confusion_matrix'][1][0]}",
            f"  True Positives:  {training_results['confusion_matrix'][1][1]}",
            "",
            "=" * 60
        ])
        
        return "\n".join(report_lines)

class MLTrainingPipeline:
    """Complete ML training pipeline orchestrator"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.data_generator = TrainingDataGenerator()
        self.model_trainer = MLModelTrainer()
        
        self.logger.info("MLTrainingPipeline initialized")
    
    def run_training_pipeline(self) -> Dict[str, Any]:
        """Execute the complete training pipeline"""
        
        self.logger.info("Starting ML training pipeline...")
        
        try:
            # Generate training data
            X, y = self.data_generator.generate_training_dataset()
            
            if len(X) == 0:
                raise ValueError("No training data generated")
            
            # Train model
            training_results = self.model_trainer.train_model(X, y)
            
            # Create and save training report
            report = self.model_trainer.create_training_report(training_results)
            
            report_path = Path("reports/ml_training_report.txt")
            report_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(report_path, 'w') as f:
                f.write(report)
            
            self.logger.info(f"Training report saved to {report_path}")
            self.logger.info("ML training pipeline completed successfully")
            
            return training_results
            
        except Exception as e:
            self.logger.error(f"Training pipeline failed: {e}")
            raise

def main():
    """Main function to run the training pipeline"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    pipeline = MLTrainingPipeline()
    results = pipeline.run_training_pipeline()
    
    print("\nTraining Pipeline Completed!")
    print(f"Final F1 Score: {results['test_performance']['f1_score']:.3f}")
    print(f"ROC AUC Score: {results['test_performance']['roc_auc']:.3f}")

if __name__ == "__main__":
    main() 