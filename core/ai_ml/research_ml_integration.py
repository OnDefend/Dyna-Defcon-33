#!/usr/bin/env python3
"""
Research ML Integration for AODS

Comprehensive integration of research datasets with AODS ML training pipeline
to enhance vulnerability detection accuracy through academic-grade training data.

This module bridges the research datasets integration with the existing AODS
ML infrastructure to provide:

- Enhanced training data from 7 research datasets
- Improved ML model accuracy with expert-curated samples
- Advanced false positive reduction training
- Benchmarking and validation capabilities
- Continuous learning from research data

Integrates with:
- core/ml_integration_manager.py
- core/ml_training_pipeline.py  
- core/ml_vulnerability_classifier.py
- core/ai_ml/external_training_data_integration.py
- data/research_training/* (research datasets)

"""

import logging
import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
import hashlib
import pickle
from concurrent.futures import ThreadPoolExecutor
import threading
import time

# ML Libraries
try:
    from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score, 
        roc_auc_score, classification_report, confusion_matrix
    )
    from sklearn.ensemble import RandomForestClassifier, VotingClassifier, GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.calibration import CalibratedClassifierCV
    import xgboost as xgb
    ML_AVAILABLE = True
except ImportError as e:
    logging.warning(f"ML libraries not available: {e}")
    ML_AVAILABLE = False

# AODS Core ML Components
try:
    from core.ml_integration_manager import MLIntegrationManager, ClassificationResult
    from core.ml_training_pipeline import MLTrainingPipeline, TrainingDataGenerator
    from core.ml_vulnerability_classifier import AdaptiveVulnerabilityML, MLVulnerabilityClassifier
    from core.ml_false_positive_reducer import OptimizedMLFalsePositiveReducer
    from .external_training_data_integration import ExternalDataIntegrator
    AODS_ML_AVAILABLE = True
except ImportError as e:
    logging.warning(f"AODS ML components not available: {e}")
    AODS_ML_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ResearchMLConfig:
    """Configuration for research ML integration."""
    research_data_dir: str = "data/research_training"
    external_data_dir: str = "data/external_training"
    models_dir: str = "models/research_enhanced"
    output_dir: str = "output/research_ml_integration"
    
    # Training parameters
    test_size: float = 0.2
    random_state: int = 42
    cv_folds: int = 5
    max_training_samples: int = 50000
    min_confidence: float = 0.7
    balance_classes: bool = True
    
    # Model parameters
    ensemble_models: List[str] = field(default_factory=lambda: [
        'random_forest', 'gradient_boosting', 'logistic_regression', 
        'neural_network', 'xgboost'
    ])
    
    # Performance thresholds
    target_accuracy: float = 0.90
    target_precision: float = 0.88
    target_recall: float = 0.92
    target_f1: float = 0.90
    max_false_positive_rate: float = 0.05


@dataclass  
class MLTrainingResult:
    """Result from ML training with research data."""
    model_name: str
    training_samples: int
    test_samples: int
    research_samples: int
    external_samples: int
    
    # Performance metrics
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    
    # Advanced metrics
    false_positive_rate: float
    false_negative_rate: float
    confusion_matrix: List[List[int]]
    
    # Research-specific metrics
    droidbench_accuracy: float = 0.0
    ghera_accuracy: float = 0.0
    d2a_fp_reduction: float = 0.0
    owapp_benchmark_score: float = 0.0
    
    # Training metadata
    training_duration: float = 0.0
    model_size_mb: float = 0.0
    feature_count: int = 0
    training_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def meets_targets(self, config: ResearchMLConfig) -> bool:
        """Check if training results meet target performance."""
        return (
            self.accuracy >= config.target_accuracy and
            self.precision >= config.target_precision and
            self.recall >= config.target_recall and
            self.f1_score >= config.target_f1 and
            self.false_positive_rate <= config.max_false_positive_rate
        )


class ResearchDatasetLoader:
    """Loads and preprocesses research datasets for ML training."""
    
    def __init__(self, config: ResearchMLConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize paths
        self.research_dir = Path(config.research_data_dir)
        self.external_dir = Path(config.external_data_dir)
        
        # Data containers
        self.research_data = []
        self.external_data = []
        self.combined_data = []
        
        # Statistics
        self.stats = {
            "research_datasets": 0,
            "external_datasets": 0,
            "total_samples": 0,
            "vulnerable_samples": 0,
            "safe_samples": 0,
            "dataset_distribution": {},
            "vulnerability_type_distribution": {},
            "load_timestamp": None
        }
    
    def load_research_datasets(self) -> List[Dict[str, Any]]:
        """Load all research training datasets."""
        self.logger.info("Loading research datasets...")
        
        research_files = []
        if self.research_dir.exists():
            research_files = list(self.research_dir.glob("*.json"))
        
        self.research_data = []
        dataset_count = 0
        
        for file_path in research_files:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # Add dataset metadata
                dataset_name = file_path.stem.replace('_training_data', '')
                for sample in data:
                    sample['dataset_source'] = 'research'
                    sample['dataset_name'] = dataset_name
                    sample['file_source'] = str(file_path)
                    
                self.research_data.extend(data)
                dataset_count += 1
                
                self.logger.info(f"Loaded {len(data)} samples from {file_path.name}")
                
            except Exception as e:
                self.logger.error(f"Failed to load research dataset {file_path}: {e}")
        
        self.stats["research_datasets"] = dataset_count
        self.logger.info(f"Loaded {len(self.research_data)} total research samples from {dataset_count} datasets")
        
        return self.research_data
    
    def load_external_datasets(self) -> List[Dict[str, Any]]:
        """Load external training datasets (NVD, GitHub, etc.)."""
        self.logger.info("Loading external datasets...")
        
        external_files = []
        if self.external_dir.exists():
            external_files = list(self.external_dir.glob("*.json"))
        
        self.external_data = []
        dataset_count = 0
        
        for file_path in external_files:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # Handle different data formats
                if isinstance(data, dict):
                    if 'training_data' in data:
                        samples = data['training_data']
                    else:
                        samples = [data]
                else:
                    samples = data
                
                # Add dataset metadata
                dataset_name = file_path.stem
                for sample in samples:
                    if isinstance(sample, dict):
                        sample['dataset_source'] = 'external'
                        sample['dataset_name'] = dataset_name
                        sample['file_source'] = str(file_path)
                
                self.external_data.extend(samples)
                dataset_count += 1
                
                self.logger.info(f"Loaded {len(samples)} samples from {file_path.name}")
                
            except Exception as e:
                self.logger.error(f"Failed to load external dataset {file_path}: {e}")
        
        self.stats["external_datasets"] = dataset_count
        self.logger.info(f"Loaded {len(self.external_data)} total external samples from {dataset_count} datasets")
        
        return self.external_data
    
    def combine_and_balance_datasets(self) -> List[Dict[str, Any]]:
        """Combine research and external data with balancing."""
        self.logger.info("Combining and balancing datasets...")
        
        # Combine all data
        all_data = self.research_data + self.external_data
        
        # Filter by confidence if specified
        if self.config.min_confidence > 0:
            filtered_data = []
            for sample in all_data:
                confidence = sample.get('confidence', 0.5)
                if confidence >= self.config.min_confidence:
                    filtered_data.append(sample)
            
            self.logger.info(f"Filtered by confidence {self.config.min_confidence}: "
                           f"{len(filtered_data)}/{len(all_data)} samples retained")
            all_data = filtered_data
        
        # Balance classes if requested
        if self.config.balance_classes and ML_AVAILABLE:
            df = pd.DataFrame(all_data)
            
            if 'label' in df.columns:
                vulnerable_samples = df[df['label'] == 1]
                safe_samples = df[df['label'] == 0]
                
                # Balance to smaller class
                min_size = min(len(vulnerable_samples), len(safe_samples))
                max_size = max(len(vulnerable_samples), len(safe_samples))
                
                self.logger.info(f"Class distribution before balancing: "
                               f"Vulnerable={len(vulnerable_samples)}, Safe={len(safe_samples)}")
                
                if min_size > 0:
                    # Undersample larger class or oversample smaller class
                    if max_size / min_size > 2:  # Significant imbalance
                        # Oversample minority class
                        from sklearn.utils import resample
                        if len(vulnerable_samples) < len(safe_samples):
                            vulnerable_balanced = resample(vulnerable_samples, 
                                                         n_samples=len(safe_samples),
                                                         random_state=self.config.random_state)
                            balanced_df = pd.concat([vulnerable_balanced, safe_samples])
                        else:
                            safe_balanced = resample(safe_samples,
                                                   n_samples=len(vulnerable_samples),
                                                   random_state=self.config.random_state)
                            balanced_df = pd.concat([vulnerable_samples, safe_balanced])
                    else:
                        # Undersample majority class
                        vulnerable_balanced = resample(vulnerable_samples,
                                                     n_samples=min_size,
                                                     random_state=self.config.random_state)
                        safe_balanced = resample(safe_samples,
                                               n_samples=min_size,
                                               random_state=self.config.random_state)
                        balanced_df = pd.concat([vulnerable_balanced, safe_balanced])
                    
                    all_data = balanced_df.to_dict('records')
                    
                    vulnerable_count = sum(1 for sample in all_data if sample.get('label') == 1)
                    safe_count = len(all_data) - vulnerable_count
                    
                    self.logger.info(f"Class distribution after balancing: "
                                   f"Vulnerable={vulnerable_count}, Safe={safe_count}")
        
        # Limit total samples if specified
        if self.config.max_training_samples and len(all_data) > self.config.max_training_samples:
            from sklearn.utils import shuffle
            all_data = shuffle(all_data, random_state=self.config.random_state)
            all_data = all_data[:self.config.max_training_samples]
            
            self.logger.info(f"Limited to {len(all_data)} samples (max={self.config.max_training_samples})")
        
        self.combined_data = all_data
        
        # Update statistics
        self._update_statistics()
        
        self.logger.info(f"Final combined dataset: {len(self.combined_data)} samples")
        return self.combined_data
    
    def _update_statistics(self):
        """Update dataset statistics."""
        self.stats["total_samples"] = len(self.combined_data)
        self.stats["vulnerable_samples"] = sum(1 for s in self.combined_data if s.get('label') == 1)
        self.stats["safe_samples"] = self.stats["total_samples"] - self.stats["vulnerable_samples"]
        self.stats["load_timestamp"] = datetime.now().isoformat()
        
        # Dataset distribution
        dataset_dist = {}
        for sample in self.combined_data:
            dataset = sample.get('dataset_name', 'unknown')
            dataset_dist[dataset] = dataset_dist.get(dataset, 0) + 1
        self.stats["dataset_distribution"] = dataset_dist
        
        # Vulnerability type distribution
        vuln_type_dist = {}
        for sample in self.combined_data:
            vuln_type = sample.get('vulnerability_type', 'unknown')
            vuln_type_dist[vuln_type] = vuln_type_dist.get(vuln_type, 0) + 1
        self.stats["vulnerability_type_distribution"] = vuln_type_dist
    
    def get_dataset_statistics(self) -> Dict[str, Any]:
        """Get comprehensive dataset statistics."""
        return self.stats.copy()


class ResearchEnhancedMLTrainer:
    """ML trainer enhanced with research datasets."""
    
    def __init__(self, config: ResearchMLConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.dataset_loader = ResearchDatasetLoader(config)
        
        # Create directories
        Path(config.models_dir).mkdir(parents=True, exist_ok=True)
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
        
        # ML components
        self.feature_extractor = None
        self.models = {}
        self.ensemble_model = None
        self.training_results = []
        
        # Integration with existing AODS ML
        self.aods_ml_manager = None
        self.external_integrator = None
        
        if AODS_ML_AVAILABLE:
            try:
                self.aods_ml_manager = MLIntegrationManager()
                self.external_integrator = ExternalDataIntegrator()
            except Exception as e:
                self.logger.warning(f"AODS ML components initialization failed: {e}")
    
    def load_training_data(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Load and prepare all training data."""
        self.logger.info("Loading research and external training data...")
        
        # Load research datasets
        research_data = self.dataset_loader.load_research_datasets()
        
        # Load external datasets  
        external_data = self.dataset_loader.load_external_datasets()
        
        # Combine and balance
        combined_data = self.dataset_loader.combine_and_balance_datasets()
        
        # Get statistics
        stats = self.dataset_loader.get_dataset_statistics()
        
        self.logger.info(f"Training data loaded: {stats['total_samples']} samples "
                        f"({stats['vulnerable_samples']} vulnerable, {stats['safe_samples']} safe)")
        
        return combined_data, stats
    
    def extract_features(self, data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features from training data."""
        self.logger.info("Extracting features from training data...")
        
        if not ML_AVAILABLE:
            raise RuntimeError("ML libraries not available for feature extraction")
        
        # Initialize feature extractors
        tfidf_vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            stop_words='english'
        )
        
        label_encoder = LabelEncoder()
        scaler = StandardScaler()
        
        # Extract text features
        texts = []
        labels = []
        metadata_features = []
        
        for sample in data:
            # Text content
            text = sample.get('text', '')
            if not text:
                # Fallback to other text fields
                text = sample.get('content', sample.get('description', ''))
            texts.append(text)
            
            # Labels
            label = sample.get('label', 0)
            labels.append(int(label))
            
            # Metadata features
            confidence = float(sample.get('confidence', 0.5))
            severity = sample.get('severity', 'MEDIUM')
            vuln_type = sample.get('vulnerability_type', 'OTHER')
            
            # Convert severity to numeric
            severity_map = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'INFO': 0}
            severity_numeric = severity_map.get(severity, 2)
            
            # Metadata feature vector
            meta_features = [
                confidence,
                severity_numeric,
                len(text),
                text.count(' '),  # Word count proxy
            ]
            metadata_features.append(meta_features)
        
        # Transform text features
        text_features = tfidf_vectorizer.fit_transform(texts)
        
        # Transform metadata features
        metadata_features = np.array(metadata_features)
        metadata_features_scaled = scaler.fit_transform(metadata_features)
        
        # Combine features
        combined_features = np.hstack([
            text_features.toarray(),
            metadata_features_scaled
        ])
        
        labels = np.array(labels)
        
        # Store feature extractors
        self.feature_extractor = {
            'tfidf_vectorizer': tfidf_vectorizer,
            'scaler': scaler,
            'feature_count': combined_features.shape[1]
        }
        
        self.logger.info(f"Extracted {combined_features.shape[1]} features from {len(data)} samples")
        
        return combined_features, labels
    
    def train_enhanced_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, MLTrainingResult]:
        """Train enhanced ML models with research data."""
        self.logger.info("Training enhanced ML models...")
        
        if not ML_AVAILABLE:
            raise RuntimeError("ML libraries not available for training")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=self.config.test_size,
            random_state=self.config.random_state,
            stratify=y
        )
        
        self.logger.info(f"Training set: {len(X_train)} samples, Test set: {len(X_test)} samples")
        
        # Define models to train
        model_configs = {
            'random_forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                random_state=self.config.random_state,
                n_jobs=-1,
                class_weight='balanced'
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=8,
                random_state=self.config.random_state
            ),
            'logistic_regression': LogisticRegression(
                random_state=self.config.random_state,
                max_iter=1000,
                class_weight='balanced'
            ),
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(200, 100, 50),
                random_state=self.config.random_state,
                max_iter=500,
                early_stopping=True
            )
        }
        
        # Add XGBoost if available
        try:
            model_configs['xgboost'] = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=8,
                random_state=self.config.random_state,
                eval_metric='logloss'
            )
        except:
            self.logger.warning("XGBoost not available, skipping")
        
        # Train individual models
        training_results = {}
        trained_models = []
        
        for model_name, model in model_configs.items():
            if model_name not in self.config.ensemble_models:
                continue
            
            try:
                self.logger.info(f"Training {model_name}...")
                start_time = time.time()
                
                # Train model
                model.fit(X_train, y_train)
                
                # Predict
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else y_pred
                
                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred, average='binary')
                recall = recall_score(y_test, y_pred, average='binary')
                f1 = f1_score(y_test, y_pred, average='binary')
                roc_auc = roc_auc_score(y_test, y_pred_proba) if len(np.unique(y_test)) > 1 else 0.0
                
                # Confusion matrix
                cm = confusion_matrix(y_test, y_pred)
                tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
                
                training_duration = time.time() - start_time
                
                # Create result
                result = MLTrainingResult(
                    model_name=model_name,
                    training_samples=len(X_train),
                    test_samples=len(X_test),
                    research_samples=self.dataset_loader.stats['research_datasets'],
                    external_samples=self.dataset_loader.stats['external_datasets'],
                    accuracy=accuracy,
                    precision=precision,
                    recall=recall,
                    f1_score=f1,
                    roc_auc=roc_auc,
                    false_positive_rate=fpr,
                    false_negative_rate=fnr,
                    confusion_matrix=cm.tolist(),
                    training_duration=training_duration,
                    feature_count=X.shape[1]
                )
                
                training_results[model_name] = result
                trained_models.append((model_name, model))
                
                self.logger.info(f"{model_name} - Accuracy: {accuracy:.3f}, F1: {f1:.3f}, "
                               f"Precision: {precision:.3f}, Recall: {recall:.3f}")
                
            except Exception as e:
                self.logger.error(f"Failed to train {model_name}: {e}")
        
        # Create ensemble model
        if len(trained_models) >= 2:
            self.logger.info("Creating ensemble model...")
            
            ensemble_estimators = [(name, model) for name, model in trained_models]
            ensemble_model = VotingClassifier(
                estimators=ensemble_estimators,
                voting='soft'
            )
            
            # Train ensemble
            ensemble_model.fit(X_train, y_train)
            
            # Evaluate ensemble
            y_pred = ensemble_model.predict(X_test)
            y_pred_proba = ensemble_model.predict_proba(X_test)[:, 1]
            
            # Calculate ensemble metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='binary')
            recall = recall_score(y_test, y_pred, average='binary')
            f1 = f1_score(y_test, y_pred, average='binary')
            roc_auc = roc_auc_score(y_test, y_pred_proba)
            
            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
            
            ensemble_result = MLTrainingResult(
                model_name='ensemble',
                training_samples=len(X_train),
                test_samples=len(X_test),
                research_samples=self.dataset_loader.stats['research_datasets'],
                external_samples=self.dataset_loader.stats['external_datasets'],
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                roc_auc=roc_auc,
                false_positive_rate=fpr,
                false_negative_rate=fnr,
                confusion_matrix=cm.tolist(),
                feature_count=X.shape[1]
            )
            
            training_results['ensemble'] = ensemble_result
            self.ensemble_model = ensemble_model
            
            self.logger.info(f"Ensemble - Accuracy: {accuracy:.3f}, F1: {f1:.3f}, "
                           f"Precision: {precision:.3f}, Recall: {recall:.3f}")
        
        # Store models and results
        self.models = dict(trained_models)
        self.training_results = list(training_results.values())
        
        return training_results
    
    def evaluate_research_benchmarks(self, training_results: Dict[str, MLTrainingResult]) -> Dict[str, float]:
        """Evaluate models on research-specific benchmarks."""
        self.logger.info("Evaluating research dataset benchmarks...")
        
        benchmarks = {}
        
        # Get best performing model
        best_model_name = max(training_results.keys(), key=lambda k: training_results[k].f1_score)
        best_model = self.models.get(best_model_name) or self.ensemble_model
        
        if not best_model:
            return benchmarks
        
        # Load research data for evaluation
        research_data = self.dataset_loader.research_data
        
        # Evaluate on specific datasets
        dataset_evaluations = {}
        
        for dataset_name in ['droidbench', 'ghera', 'd2a', 'owapp']:
            dataset_samples = [s for s in research_data if s.get('dataset_name', '').startswith(dataset_name)]
            
            if len(dataset_samples) > 5:  # Minimum samples for evaluation
                try:
                    # Extract features for this dataset
                    texts = [s.get('text', '') for s in dataset_samples]
                    labels = [int(s.get('label', 0)) for s in dataset_samples]
                    
                    if self.feature_extractor:
                        # Transform features using same pipeline
                        text_features = self.feature_extractor['tfidf_vectorizer'].transform(texts)
                        
                        # Create metadata features
                        metadata_features = []
                        for sample in dataset_samples:
                            confidence = float(sample.get('confidence', 0.5))
                            severity = sample.get('severity', 'MEDIUM')
                            severity_map = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'INFO': 0}
                            severity_numeric = severity_map.get(severity, 2)
                            text = sample.get('text', '')
                            
                            meta_features = [confidence, severity_numeric, len(text), text.count(' ')]
                            metadata_features.append(meta_features)
                        
                        metadata_features_scaled = self.feature_extractor['scaler'].transform(metadata_features)
                        
                        # Combine features
                        combined_features = np.hstack([text_features.toarray(), metadata_features_scaled])
                        
                        # Predict
                        predictions = best_model.predict(combined_features)
                        accuracy = accuracy_score(labels, predictions)
                        
                        dataset_evaluations[dataset_name] = accuracy
                        
                        self.logger.info(f"{dataset_name} benchmark accuracy: {accuracy:.3f}")
                
                except Exception as e:
                    self.logger.warning(f"Failed to evaluate {dataset_name} benchmark: {e}")
        
        # Update training results with benchmark scores
        for result in self.training_results:
            if result.model_name == best_model_name:
                result.droidbench_accuracy = dataset_evaluations.get('droidbench', 0.0)
                result.ghera_accuracy = dataset_evaluations.get('ghera', 0.0)
                result.d2a_fp_reduction = dataset_evaluations.get('d2a', 0.0)
                result.owapp_benchmark_score = dataset_evaluations.get('owapp', 0.0)
        
        return dataset_evaluations
    
    def save_models_and_results(self) -> bool:
        """Save trained models and results."""
        try:
            models_dir = Path(self.config.models_dir)
            
            # Save individual models
            for model_name, model in self.models.items():
                model_file = models_dir / f"{model_name}_research_enhanced.pkl"
                with open(model_file, 'wb') as f:
                    pickle.dump(model, f)
                
                self.logger.info(f"Saved {model_name} model to {model_file}")
            
            # Save ensemble model
            if self.ensemble_model:
                ensemble_file = models_dir / "ensemble_research_enhanced.pkl"
                with open(ensemble_file, 'wb') as f:
                    pickle.dump(self.ensemble_model, f)
                
                self.logger.info(f"Saved ensemble model to {ensemble_file}")
            
            # Save feature extractor
            if self.feature_extractor:
                feature_file = models_dir / "feature_extractor_research_enhanced.pkl"
                with open(feature_file, 'wb') as f:
                    pickle.dump(self.feature_extractor, f)
            
            # Save training results
            results_file = Path(self.config.output_dir) / "training_results.json"
            with open(results_file, 'w') as f:
                results_data = [asdict(result) for result in self.training_results]
                json.dump(results_data, f, indent=2, default=str)
            
            # Save dataset statistics
            stats_file = Path(self.config.output_dir) / "dataset_statistics.json"
            with open(stats_file, 'w') as f:
                json.dump(self.dataset_loader.get_dataset_statistics(), f, indent=2, default=str)
            
            self.logger.info("Models and results saved successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save models and results: {e}")
            return False
    
    def integrate_with_aods_ml(self) -> bool:
        """Integrate enhanced models with existing AODS ML system."""
        if not AODS_ML_AVAILABLE or not self.aods_ml_manager:
            self.logger.warning("AODS ML components not available for integration")
            return False
        
        try:
            self.logger.info("Integrating enhanced models with AODS ML system...")
            
            # Get training data in AODS format
            combined_data, _ = self.load_training_data()
            
            # Convert to AODS feedback format
            for sample in combined_data[:1000]:  # Limit for performance
                try:
                    # Add to vulnerability detector feedback
                    if hasattr(self.aods_ml_manager, 'vulnerability_detector'):
                        self.aods_ml_manager.vulnerability_detector.add_feedback(
                            text=sample.get('text', ''),
                            actual_result=bool(sample.get('label', 0)),
                            user_feedback=f"Research data from {sample.get('dataset_name', 'unknown')}"
                        )
                    
                    # Add to false positive reducer feedback  
                    if hasattr(self.aods_ml_manager, 'fp_reducer'):
                        self.aods_ml_manager.fp_reducer.add_feedback(
                            text=sample.get('text', ''),
                            is_actual_fp=(sample.get('label', 0) == 0),
                            user_notes=f"Research data: {sample.get('vulnerability_type', 'unknown')}"
                        )
                
                except Exception as e:
                    self.logger.warning(f"Failed to add sample to AODS feedback: {e}")
            
            # Trigger AODS model retraining with research data
            if hasattr(self.aods_ml_manager, 'train_from_feedback'):
                training_results = self.aods_ml_manager.train_from_feedback()
                self.logger.info(f"AODS ML training results: {training_results}")
            
            self.logger.info("Successfully integrated enhanced models with AODS ML system")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to integrate with AODS ML system: {e}")
            return False


class ResearchMLIntegrationManager:
    """Main manager for research ML integration."""
    
    def __init__(self, config: Optional[ResearchMLConfig] = None):
        self.config = config or ResearchMLConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize trainer
        self.trainer = ResearchEnhancedMLTrainer(self.config)
        
        # Results
        self.integration_results = {}
        self.integration_timestamp = None
    
    def run_complete_integration(self) -> Dict[str, Any]:
        """Run complete research ML integration pipeline."""
        self.logger.info("Starting complete research ML integration...")
        
        start_time = time.time()
        self.integration_timestamp = datetime.now()
        
        try:
            # Step 1: Load training data
            self.logger.info("Step 1: Loading training data...")
            training_data, data_stats = self.trainer.load_training_data()
            
            if len(training_data) < 10:
                raise ValueError("Insufficient training data for ML training")
            
            # Step 2: Extract features
            self.logger.info("Step 2: Extracting features...")
            X, y = self.trainer.extract_features(training_data)
            
            # Step 3: Train enhanced models
            self.logger.info("Step 3: Training enhanced ML models...")
            training_results = self.trainer.train_enhanced_models(X, y)
            
            # Step 4: Evaluate research benchmarks
            self.logger.info("Step 4: Evaluating research benchmarks...")
            benchmark_results = self.trainer.evaluate_research_benchmarks(training_results)
            
            # Step 5: Save models and results
            self.logger.info("Step 5: Saving models and results...")
            save_success = self.trainer.save_models_and_results()
            
            # Step 6: Integrate with AODS ML
            self.logger.info("Step 6: Integrating with AODS ML system...")
            aods_integration_success = self.trainer.integrate_with_aods_ml()
            
            # Calculate overall metrics
            best_result = max(training_results.values(), key=lambda r: r.f1_score)
            
            integration_duration = time.time() - start_time
            
            # Compile results
            self.integration_results = {
                "success": True,
                "integration_timestamp": self.integration_timestamp.isoformat(),
                "integration_duration": integration_duration,
                "data_statistics": data_stats,
                "training_results": {k: asdict(v) for k, v in training_results.items()},
                "benchmark_results": benchmark_results,
                "best_model": {
                    "name": best_result.model_name,
                    "accuracy": best_result.accuracy,
                    "precision": best_result.precision,
                    "recall": best_result.recall,
                    "f1_score": best_result.f1_score,
                    "false_positive_rate": best_result.false_positive_rate
                },
                "performance_targets_met": best_result.meets_targets(self.config),
                "models_saved": save_success,
                "aods_integration": aods_integration_success,
                "total_training_samples": len(training_data),
                "research_datasets_count": data_stats.get('research_datasets', 0),
                "external_datasets_count": data_stats.get('external_datasets', 0)
            }
            
            self.logger.info(f"Research ML integration completed successfully in {integration_duration:.2f}s")
            self.logger.info(f"Best model: {best_result.model_name} (F1: {best_result.f1_score:.3f})")
            
            return self.integration_results
            
        except Exception as e:
            self.logger.error(f"Research ML integration failed: {e}")
            
            self.integration_results = {
                "success": False,
                "error": str(e),
                "integration_timestamp": self.integration_timestamp.isoformat() if self.integration_timestamp else None,
                "integration_duration": time.time() - start_time
            }
            
            return self.integration_results
    
    def generate_integration_report(self) -> str:
        """Generate comprehensive integration report."""
        if not self.integration_results:
            return "No integration results available."
        
        report = []
        report.append("=" * 80)
        report.append("AODS RESEARCH ML INTEGRATION REPORT")
        report.append("=" * 80)
        
        if self.integration_results.get("success"):
            report.append("✅ INTEGRATION SUCCESSFUL")
            
            # Summary
            report.append(f"\n📊 INTEGRATION SUMMARY:")
            report.append(f"   • Duration: {self.integration_results['integration_duration']:.2f} seconds")
            report.append(f"   • Training Samples: {self.integration_results['total_training_samples']:,}")
            report.append(f"   • Research Datasets: {self.integration_results['research_datasets_count']}")
            report.append(f"   • External Datasets: {self.integration_results['external_datasets_count']}")
            
            # Best model performance
            best_model = self.integration_results.get("best_model", {})
            report.append(f"\n🎯 BEST MODEL PERFORMANCE:")
            report.append(f"   • Model: {best_model.get('name', 'unknown')}")
            report.append(f"   • Accuracy: {best_model.get('accuracy', 0):.3f}")
            report.append(f"   • Precision: {best_model.get('precision', 0):.3f}")
            report.append(f"   • Recall: {best_model.get('recall', 0):.3f}")
            report.append(f"   • F1-Score: {best_model.get('f1_score', 0):.3f}")
            report.append(f"   • False Positive Rate: {best_model.get('false_positive_rate', 0):.3f}")
            
            # Performance targets
            targets_met = self.integration_results.get("performance_targets_met", False)
            report.append(f"\n🎯 PERFORMANCE TARGETS: {'✅ MET' if targets_met else '⚠️ NOT MET'}")
            
            # Research benchmarks
            benchmarks = self.integration_results.get("benchmark_results", {})
            if benchmarks:
                report.append(f"\n🏆 RESEARCH BENCHMARK RESULTS:")
                for dataset, accuracy in benchmarks.items():
                    report.append(f"   • {dataset.upper()}: {accuracy:.3f}")
            
            # Integration status
            models_saved = self.integration_results.get("models_saved", False)
            aods_integration = self.integration_results.get("aods_integration", False)
            
            report.append(f"\n🔧 INTEGRATION STATUS:")
            report.append(f"   • Models Saved: {'✅' if models_saved else '❌'}")
            report.append(f"   • AODS ML Integration: {'✅' if aods_integration else '❌'}")
            
        else:
            report.append("❌ INTEGRATION FAILED")
            error = self.integration_results.get("error", "Unknown error")
            report.append(f"\n❌ Error: {error}")
        
        report.append("\n" + "=" * 80)
        
        return "\n".join(report)


# Main execution function
def run_research_ml_integration(config: Optional[ResearchMLConfig] = None) -> Dict[str, Any]:
    """
    Run complete research ML integration.
    
    Args:
        config: Optional configuration (uses defaults if not provided)
        
    Returns:
        Integration results
    """
    manager = ResearchMLIntegrationManager(config)
    results = manager.run_complete_integration()
    
    # Print report
    print(manager.generate_integration_report())
    
    return results


if __name__ == "__main__":
    # Example usage
    config = ResearchMLConfig(
        max_training_samples=10000,
        target_accuracy=0.90,
        target_f1=0.88
    )
    
    results = run_research_ml_integration(config)
    
    if results.get("success"):
        print("🎉 Research ML integration completed successfully!")
    else:
        print("💥 Research ML integration failed.") 