#!/usr/bin/env python3
"""
Real-Time False Positive Learning System
Part of ML-002: D2A False Positive Reduction Integration

This module implements real-time learning from false positive feedback
to continuously improve the accuracy of vulnerability detection.
"""

import logging
import json
import pickle
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class FalsePositiveFeedback:
    """Structure for false positive feedback data."""
    finding_id: str
    file_path: str
    vulnerability_type: str
    confidence_score: float
    is_false_positive: bool
    feedback_source: str  # 'user', 'automated', 'expert_review'
    timestamp: datetime
    context_data: Dict[str, Any]
    correction_reason: Optional[str] = None
    reviewer_id: Optional[str] = None

@dataclass
class LearningPattern:
    """Pattern learned from false positive feedback."""
    pattern_id: str
    pattern_type: str  # 'file_pattern', 'context_pattern', 'confidence_threshold'
    pattern_data: Dict[str, Any]
    effectiveness_score: float
    usage_count: int
    created_timestamp: datetime
    last_updated: datetime

class RealTimeFalsePositiveLearner:
    """Real-time learning system for false positive reduction."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.learning_config = config.get('false_positive_learning', {})
        self.data_dir = Path(self.learning_config.get('data_dir', 'data/fp_learning'))
        self.models_dir = Path(self.learning_config.get('models_dir', 'models/fp_learning'))
        
        # Create directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Learning parameters
        self.min_feedback_count = self.learning_config.get('min_feedback_count', 5)
        self.learning_threshold = self.learning_config.get('learning_threshold', 0.7)
        self.pattern_effectiveness_threshold = self.learning_config.get('pattern_effectiveness', 0.8)
        self.max_feedback_age_days = self.learning_config.get('max_feedback_age_days', 30)
        
        # In-memory storage
        self.feedback_history: List[FalsePositiveFeedback] = []
        self.learned_patterns: Dict[str, LearningPattern] = {}
        self.pattern_effectiveness: Dict[str, float] = {}
        
        # Learning thread
        self.learning_thread = None
        self.learning_active = False
        self.learning_interval = self.learning_config.get('learning_interval_seconds', 300)  # 5 minutes
        
        # Load existing data
        self._load_existing_data()
        
        logger.info(f"RealTimeFalsePositiveLearner initialized with {len(self.feedback_history)} historical feedback items")
    
    def _load_existing_data(self):
        """Load existing feedback and patterns from disk."""
        try:
            # Load feedback history
            feedback_file = self.data_dir / 'feedback_history.json'
            if feedback_file.exists():
                with open(feedback_file, 'r') as f:
                    feedback_data = json.load(f)
                    for item in feedback_data:
                        item['timestamp'] = datetime.fromisoformat(item['timestamp'])
                        self.feedback_history.append(FalsePositiveFeedback(**item))
            
            # Load learned patterns
            patterns_file = self.models_dir / 'learned_patterns.pkl'
            if patterns_file.exists():
                with open(patterns_file, 'rb') as f:
                    self.learned_patterns = pickle.load(f)
            
            logger.info(f"Loaded {len(self.feedback_history)} feedback items and {len(self.learned_patterns)} patterns")
            
        except Exception as e:
            logger.error(f"Failed to load existing data: {e}")
    
    def _save_data(self):
        """Save feedback and patterns to disk."""
        try:
            # Save feedback history
            feedback_file = self.data_dir / 'feedback_history.json'
            feedback_data = []
            for feedback in self.feedback_history:
                item = asdict(feedback)
                item['timestamp'] = feedback.timestamp.isoformat()
                feedback_data.append(item)
            
            with open(feedback_file, 'w') as f:
                json.dump(feedback_data, f, indent=2)
            
            # Save learned patterns
            patterns_file = self.models_dir / 'learned_patterns.pkl'
            with open(patterns_file, 'wb') as f:
                pickle.dump(self.learned_patterns, f)
            
            logger.debug("Data saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save data: {e}")
    
    def add_feedback(self, feedback: FalsePositiveFeedback):
        """Add new false positive feedback for learning."""
        # Add to history
        self.feedback_history.append(feedback)
        
        # Trigger immediate pattern update if enough feedback
        recent_feedback = self._get_recent_feedback(feedback.vulnerability_type)
        if len(recent_feedback) >= self.min_feedback_count:
            self._update_patterns_for_type(feedback.vulnerability_type)
        
        # Save data
        self._save_data()
        
        logger.info(f"Added feedback for {feedback.vulnerability_type} - FP: {feedback.is_false_positive}")
    
    def _get_recent_feedback(self, vulnerability_type: str, days: int = None) -> List[FalsePositiveFeedback]:
        """Get recent feedback for a specific vulnerability type."""
        cutoff_date = datetime.now() - timedelta(days=days or self.max_feedback_age_days)
        
        return [
            feedback for feedback in self.feedback_history
            if (feedback.vulnerability_type == vulnerability_type and
                feedback.timestamp >= cutoff_date)
        ]
    
    def _update_patterns_for_type(self, vulnerability_type: str):
        """Update learned patterns for a specific vulnerability type."""
        recent_feedback = self._get_recent_feedback(vulnerability_type)
        
        if len(recent_feedback) < self.min_feedback_count:
            return
        
        # Analyze false positive patterns
        fp_feedback = [f for f in recent_feedback if f.is_false_positive]
        tp_feedback = [f for f in recent_feedback if not f.is_false_positive]
        
        if len(fp_feedback) < 2:
            return
        
        # Learn file path patterns
        self._learn_file_path_patterns(vulnerability_type, fp_feedback, tp_feedback)
        
        # Learn context patterns
        self._learn_context_patterns(vulnerability_type, fp_feedback, tp_feedback)
        
        # Learn confidence threshold patterns
        self._learn_confidence_patterns(vulnerability_type, fp_feedback, tp_feedback)
        
        logger.info(f"Updated patterns for {vulnerability_type} based on {len(recent_feedback)} feedback items")
    
    def _learn_file_path_patterns(self, vuln_type: str, fp_feedback: List, tp_feedback: List):
        """Learn file path patterns that indicate false positives."""
        # Analyze common file paths in false positives
        fp_paths = [f.file_path for f in fp_feedback]
        tp_paths = [f.file_path for f in tp_feedback]
        
        # Find patterns more common in FPs than TPs
        fp_path_patterns = self._extract_path_patterns(fp_paths)
        tp_path_patterns = self._extract_path_patterns(tp_paths)
        
        for pattern, fp_count in fp_path_patterns.items():
            tp_count = tp_path_patterns.get(pattern, 0)
            
            # Calculate effectiveness (higher FP rate = more effective for filtering)
            total_count = fp_count + tp_count
            if total_count >= 3:  # Minimum occurrences
                fp_rate = fp_count / total_count
                
                if fp_rate >= self.pattern_effectiveness_threshold:
                    pattern_id = f"path_pattern_{vuln_type}_{hashlib.md5(pattern.encode()).hexdigest()[:8]}"
                    
                    learned_pattern = LearningPattern(
                        pattern_id=pattern_id,
                        pattern_type='file_pattern',
                        pattern_data={
                            'vulnerability_type': vuln_type,
                            'path_pattern': pattern,
                            'fp_rate': fp_rate,
                            'total_occurrences': total_count
                        },
                        effectiveness_score=fp_rate,
                        usage_count=0,
                        created_timestamp=datetime.now(),
                        last_updated=datetime.now()
                    )
                    
                    self.learned_patterns[pattern_id] = learned_pattern
                    logger.info(f"Learned file pattern: {pattern} (FP rate: {fp_rate:.2f})")
    
    def _learn_context_patterns(self, vuln_type: str, fp_feedback: List, tp_feedback: List):
        """Learn context patterns that indicate false positives."""
        # Analyze context data patterns
        for feedback in fp_feedback:
            context = feedback.context_data
            
            # Look for common context indicators
            context_indicators = []
            
            if 'framework_detected' in context and context['framework_detected']:
                context_indicators.append('framework_code')
            
            if 'file_size' in context and context['file_size'] < 1000:
                context_indicators.append('small_file')
            
            if 'auto_generated' in context and context['auto_generated']:
                context_indicators.append('auto_generated')
            
            # Create patterns for significant indicators
            for indicator in context_indicators:
                pattern_id = f"context_pattern_{vuln_type}_{indicator}"
                
                if pattern_id not in self.learned_patterns:
                    learned_pattern = LearningPattern(
                        pattern_id=pattern_id,
                        pattern_type='context_pattern',
                        pattern_data={
                            'vulnerability_type': vuln_type,
                            'context_indicator': indicator,
                            'description': f"Context pattern for {indicator} in {vuln_type}"
                        },
                        effectiveness_score=0.8,  # Default, will be updated with usage
                        usage_count=0,
                        created_timestamp=datetime.now(),
                        last_updated=datetime.now()
                    )
                    
                    self.learned_patterns[pattern_id] = learned_pattern
    
    def _learn_confidence_patterns(self, vuln_type: str, fp_feedback: List, tp_feedback: List):
        """Learn confidence threshold patterns for different scenarios."""
        if len(fp_feedback) < 3 or len(tp_feedback) < 3:
            return
        
        fp_confidences = [f.confidence_score for f in fp_feedback]
        tp_confidences = [f.confidence_score for f in tp_feedback]
        
        # Find optimal threshold that separates FPs from TPs
        fp_avg = sum(fp_confidences) / len(fp_confidences)
        tp_avg = sum(tp_confidences) / len(tp_confidences)
        
        # If there's a clear separation, create a threshold pattern
        if tp_avg - fp_avg > 0.2:  # Significant difference
            optimal_threshold = (fp_avg + tp_avg) / 2
            
            pattern_id = f"confidence_threshold_{vuln_type}"
            
            learned_pattern = LearningPattern(
                pattern_id=pattern_id,
                pattern_type='confidence_threshold',
                pattern_data={
                    'vulnerability_type': vuln_type,
                    'optimal_threshold': optimal_threshold,
                    'fp_avg_confidence': fp_avg,
                    'tp_avg_confidence': tp_avg
                },
                effectiveness_score=min(0.9, (tp_avg - fp_avg)),
                usage_count=0,
                created_timestamp=datetime.now(),
                last_updated=datetime.now()
            )
            
            self.learned_patterns[pattern_id] = learned_pattern
            logger.info(f"Learned confidence threshold for {vuln_type}: {optimal_threshold:.2f}")
    
    def _extract_path_patterns(self, file_paths: List[str]) -> Dict[str, int]:
        """Extract common patterns from file paths."""
        patterns = defaultdict(int)
        
        for path in file_paths:
            # Directory-based patterns
            path_parts = path.split('/')
            for i, part in enumerate(path_parts):
                if part in ['kotlin', 'okhttp3', 'androidx', 'android', 'support']:
                    patterns[f"contains_{part}"] += 1
                
                # Package patterns
                if i < len(path_parts) - 1:  # Not the filename
                    if '.' in part:
                        patterns[f"package_{part}"] += 1
            
            # File extension patterns
            if '.' in path:
                ext = path.split('.')[-1]
                patterns[f"extension_{ext}"] += 1
            
            # File name patterns
            filename = path.split('/')[-1]
            if 'generated' in filename.lower():
                patterns['generated_file'] += 1
            if filename.startswith('R.'):
                patterns['resource_file'] += 1
        
        return dict(patterns)
    
    def should_filter_as_false_positive(self, finding_data: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Determine if a finding should be filtered as false positive based on learned patterns.
        
        Returns:
            (should_filter, confidence, reason)
        """
        vulnerability_type = finding_data.get('vulnerability_type', '')
        file_path = finding_data.get('file_path', '')
        confidence_score = finding_data.get('confidence_score', 0.0)
        context_data = finding_data.get('context_data', {})
        
        filter_reasons = []
        total_confidence = 0.0
        pattern_count = 0
        
        # Check learned patterns
        for pattern_id, pattern in self.learned_patterns.items():
            if pattern.pattern_data.get('vulnerability_type') != vulnerability_type:
                continue
            
            pattern_match = False
            pattern_confidence = 0.0
            
            if pattern.pattern_type == 'file_pattern':
                path_pattern = pattern.pattern_data.get('path_pattern', '')
                if path_pattern in file_path:
                    pattern_match = True
                    pattern_confidence = pattern.effectiveness_score
                    filter_reasons.append(f"File pattern: {path_pattern}")
            
            elif pattern.pattern_type == 'context_pattern':
                indicator = pattern.pattern_data.get('context_indicator', '')
                if self._check_context_indicator(indicator, context_data):
                    pattern_match = True
                    pattern_confidence = pattern.effectiveness_score
                    filter_reasons.append(f"Context pattern: {indicator}")
            
            elif pattern.pattern_type == 'confidence_threshold':
                threshold = pattern.pattern_data.get('optimal_threshold', 0.5)
                if confidence_score < threshold:
                    pattern_match = True
                    pattern_confidence = pattern.effectiveness_score
                    filter_reasons.append(f"Confidence below threshold: {threshold:.2f}")
            
            if pattern_match:
                total_confidence += pattern_confidence
                pattern_count += 1
                
                # Update pattern usage
                pattern.usage_count += 1
                pattern.last_updated = datetime.now()
        
        # Calculate overall confidence
        if pattern_count > 0:
            avg_confidence = total_confidence / pattern_count
            should_filter = avg_confidence >= self.learning_threshold
            
            reason = "; ".join(filter_reasons) if filter_reasons else "Pattern-based filtering"
            
            return should_filter, avg_confidence, reason
        
        return False, 0.0, "No matching patterns"
    
    def _check_context_indicator(self, indicator: str, context_data: Dict[str, Any]) -> bool:
        """Check if a context indicator is present."""
        if indicator == 'framework_code':
            return context_data.get('framework_detected', False)
        elif indicator == 'small_file':
            return context_data.get('file_size', float('inf')) < 1000
        elif indicator == 'auto_generated':
            return context_data.get('auto_generated', False)
        
        return False
    
    def start_learning_thread(self):
        """Start the background learning thread."""
        if self.learning_active:
            return
        
        self.learning_active = True
        self.learning_thread = threading.Thread(target=self._learning_loop, daemon=True)
        self.learning_thread.start()
        
        logger.info("Real-time learning thread started")
    
    def stop_learning_thread(self):
        """Stop the background learning thread."""
        self.learning_active = False
        if self.learning_thread:
            self.learning_thread.join(timeout=5)
        
        logger.info("Real-time learning thread stopped")
    
    def _learning_loop(self):
        """Background learning loop."""
        while self.learning_active:
            try:
                # Update patterns for all vulnerability types with recent feedback
                vuln_types = set(f.vulnerability_type for f in self.feedback_history)
                
                for vuln_type in vuln_types:
                    recent_feedback = self._get_recent_feedback(vuln_type)
                    if len(recent_feedback) >= self.min_feedback_count:
                        self._update_patterns_for_type(vuln_type)
                
                # Save data periodically
                self._save_data()
                
                # Clean old patterns and feedback
                self._cleanup_old_data()
                
                time.sleep(self.learning_interval)
                
            except Exception as e:
                logger.error(f"Error in learning loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _cleanup_old_data(self):
        """Clean up old feedback and ineffective patterns."""
        cutoff_date = datetime.now() - timedelta(days=self.max_feedback_age_days)
        
        # Remove old feedback
        old_count = len(self.feedback_history)
        self.feedback_history = [
            f for f in self.feedback_history 
            if f.timestamp >= cutoff_date
        ]
        
        if len(self.feedback_history) < old_count:
            logger.info(f"Cleaned up {old_count - len(self.feedback_history)} old feedback items")
        
        # Remove ineffective patterns
        ineffective_patterns = [
            pattern_id for pattern_id, pattern in self.learned_patterns.items()
            if (pattern.effectiveness_score < 0.6 and pattern.usage_count < 5)
        ]
        
        for pattern_id in ineffective_patterns:
            del self.learned_patterns[pattern_id]
        
        if ineffective_patterns:
            logger.info(f"Removed {len(ineffective_patterns)} ineffective patterns")
    
    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get statistics about the learning system."""
        total_feedback = len(self.feedback_history)
        fp_feedback = len([f for f in self.feedback_history if f.is_false_positive])
        
        vuln_type_stats = defaultdict(lambda: {'total': 0, 'fp': 0})
        for feedback in self.feedback_history:
            vuln_type_stats[feedback.vulnerability_type]['total'] += 1
            if feedback.is_false_positive:
                vuln_type_stats[feedback.vulnerability_type]['fp'] += 1
        
        pattern_stats = defaultdict(int)
        for pattern in self.learned_patterns.values():
            pattern_stats[pattern.pattern_type] += 1
        
        return {
            'total_feedback': total_feedback,
            'false_positive_feedback': fp_feedback,
            'true_positive_feedback': total_feedback - fp_feedback,
            'learned_patterns': len(self.learned_patterns),
            'pattern_types': dict(pattern_stats),
            'vulnerability_type_stats': dict(vuln_type_stats),
            'learning_active': self.learning_active
        }
    
    def export_patterns(self) -> Dict[str, Any]:
        """Export learned patterns for use by other components."""
        patterns_export = {}
        
        for pattern_id, pattern in self.learned_patterns.items():
            patterns_export[pattern_id] = {
                'type': pattern.pattern_type,
                'data': pattern.pattern_data,
                'effectiveness': pattern.effectiveness_score,
                'usage_count': pattern.usage_count
            }
        
        return patterns_export

class FalsePositiveFeedbackCollector:
    """Collect and manage false positive feedback from various sources."""
    
    def __init__(self, learner: RealTimeFalsePositiveLearner):
        self.learner = learner
        self.logger = logging.getLogger(__name__)
    
    def collect_user_feedback(self, finding_id: str, is_false_positive: bool, 
                            user_id: str, reason: str = None) -> bool:
        """Collect feedback from user review."""
        try:
            # This would be integrated with the UI/API
            # For now, this is a placeholder for the feedback collection mechanism
            
            feedback = FalsePositiveFeedback(
                finding_id=finding_id,
                file_path="placeholder",  # Would come from finding data
                vulnerability_type="placeholder",  # Would come from finding data
                confidence_score=0.0,  # Would come from finding data
                is_false_positive=is_false_positive,
                feedback_source='user',
                timestamp=datetime.now(),
                context_data={},  # Would come from finding data
                correction_reason=reason,
                reviewer_id=user_id
            )
            
            self.learner.add_feedback(feedback)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to collect user feedback: {e}")
            return False
    
    def collect_automated_feedback(self, finding_data: Dict[str, Any], 
                                 validation_result: bool) -> bool:
        """Collect feedback from automated validation."""
        try:
            feedback = FalsePositiveFeedback(
                finding_id=finding_data.get('finding_id', ''),
                file_path=finding_data.get('file_path', ''),
                vulnerability_type=finding_data.get('vulnerability_type', ''),
                confidence_score=finding_data.get('confidence_score', 0.0),
                is_false_positive=not validation_result,
                feedback_source='automated',
                timestamp=datetime.now(),
                context_data=finding_data.get('context_data', {}),
                correction_reason='Automated validation'
            )
            
            self.learner.add_feedback(feedback)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to collect automated feedback: {e}")
            return False 