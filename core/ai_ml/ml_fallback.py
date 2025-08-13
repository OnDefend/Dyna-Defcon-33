"""
ML Fallback System - Provides basic functionality when sklearn is not available
"""

import logging

logger = logging.getLogger(__name__)

class MLFallbackClassifier:
    """Basic fallback classifier when ML libraries are not available."""
    
    def __init__(self):
        self.is_fallback = True
        logger.warning("Using ML fallback - install scikit-learn for full functionality")
    
    def predict(self, X):
        """Provide basic predictions based on simple heuristics."""
        # Simple rule-based classification
        predictions = []
        for sample in X:
            # Basic heuristic: if sample contains certain keywords, classify as vulnerable
            if isinstance(sample, str):
                vulnerable_keywords = ['password', 'secret', 'key', 'token', 'exploit']
                score = sum(1 for keyword in vulnerable_keywords if keyword.lower() in sample.lower())
                predictions.append(1 if score > 0 else 0)
            else:
                predictions.append(0)  # Default to safe
        return predictions
    
    def predict_proba(self, X):
        """Provide basic probability predictions."""
        predictions = self.predict(X)
        return [[1-p, p] for p in predictions]
    
    def fit(self, X, y):
        """Dummy fit method for compatibility."""
        logger.info("ML fallback fit() called - no training performed")
        return self

class MLFallbackVectorizer:
    """Basic fallback vectorizer when sklearn is not available."""
    
    def __init__(self):
        self.vocabulary_ = {}
        self.is_fallback = True
    
    def fit_transform(self, texts):
        """Basic text to feature conversion."""
        # Simple bag-of-words approach
        all_words = set()
        for text in texts:
            if isinstance(text, str):
                words = text.lower().split()
                all_words.update(words)
        
        self.vocabulary_ = {word: i for i, word in enumerate(sorted(all_words))}
        
        # Create basic feature matrix
        features = []
        for text in texts:
            if isinstance(text, str):
                words = text.lower().split()
                feature_vector = [0] * len(self.vocabulary_)
                for word in words:
                    if word in self.vocabulary_:
                        feature_vector[self.vocabulary_[word]] = 1
                features.append(feature_vector)
            else:
                features.append([0] * len(self.vocabulary_))
        
        return features
    
    def transform(self, texts):
        """Transform texts using existing vocabulary."""
        features = []
        for text in texts:
            if isinstance(text, str):
                words = text.lower().split()
                feature_vector = [0] * len(self.vocabulary_)
                for word in words:
                    if word in self.vocabulary_:
                        feature_vector[self.vocabulary_[word]] = 1
                features.append(feature_vector)
            else:
                features.append([0] * len(self.vocabulary_))
        
        return features
