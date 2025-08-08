#!/usr/bin/env python3
"""
AODS Real-Time False Positive Learning Integration
Integrates the real-time learning system with AODS components
"""

import logging
import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AODSFPLearningIntegration:
    """Integration layer for real-time false positive learning."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.fp_learning_config = config.get('false_positive_learning', {})
        self.learner = None
        self.feedback_collector = None
        
        # Initialize if enabled
        if self.fp_learning_config.get('enabled', False):
            self._initialize_learning_system()
    
    def _initialize_learning_system(self):
        """Initialize the real-time learning system."""
        try:
            from core.realtime_false_positive_learner import (
                RealTimeFalsePositiveLearner, 
                FalsePositiveFeedbackCollector
            )
            
            self.learner = RealTimeFalsePositiveLearner(self.config)
            self.feedback_collector = FalsePositiveFeedbackCollector(self.learner)
            
            # Start learning thread if auto-start enabled
            if self.fp_learning_config.get('auto_start_learning', True):
                self.learner.start_learning_thread()
            
            logger.info("✅ Real-time FP learning system initialized")
            
        except ImportError as e:
            logger.warning(f"⚠️ FP learning system not available: {e}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize FP learning system: {e}")
    
    def process_finding_with_learning(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a finding with real-time learning integration."""
        if not self.learner:
            return finding_data
        
        try:
            # Check if finding should be filtered based on learned patterns
            should_filter, confidence, reason = self.learner.should_filter_as_false_positive(finding_data)
            
            # Add learning metadata to finding
            finding_data['learning_metadata'] = {
                'learned_filter_applied': should_filter,
                'learning_confidence': confidence,
                'learning_reason': reason,
                'timestamp': datetime.now().isoformat()
            }
            
            # If high confidence false positive, mark for filtering
            if should_filter and confidence > 0.8:
                finding_data['filtered_by_learning'] = True
                finding_data['filter_reason'] = f"Real-time learning: {reason}"
                logger.debug(f"Filtered finding by learning: {reason}")
            
            return finding_data
            
        except Exception as e:
            logger.error(f"Error in learning-based processing: {e}")
            return finding_data
    
    def collect_feedback(self, finding_id: str, is_false_positive: bool, 
                        source: str = 'user', reviewer_id: str = None, 
                        reason: str = None) -> bool:
        """Collect feedback for a finding."""
        if not self.feedback_collector:
            return False
        
        try:
            if source == 'user':
                return self.feedback_collector.collect_user_feedback(
                    finding_id, is_false_positive, reviewer_id or 'anonymous', reason
                )
            elif source == 'automated':
                # This would need finding data - placeholder for now
                finding_data = {'finding_id': finding_id}
                return self.feedback_collector.collect_automated_feedback(
                    finding_data, not is_false_positive
                )
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to collect feedback: {e}")
            return False
    
    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get learning system statistics."""
        if not self.learner:
            return {'status': 'not_available'}
        
        try:
            stats = self.learner.get_learning_statistics()
            stats['status'] = 'active'
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get learning statistics: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def export_learned_patterns(self) -> Dict[str, Any]:
        """Export learned patterns for external use."""
        if not self.learner:
            return {}
        
        try:
            return self.learner.export_patterns()
            
        except Exception as e:
            logger.error(f"Failed to export patterns: {e}")
            return {}
    
    def shutdown(self):
        """Shutdown the learning system."""
        if self.learner:
            self.learner.stop_learning_thread()
            logger.info("✅ Real-time FP learning system shutdown")

# Global instance for easy access
_fp_learning_integration = None

def initialize_fp_learning(config: Dict[str, Any]) -> Optional[AODSFPLearningIntegration]:
    """Initialize global FP learning integration."""
    global _fp_learning_integration
    
    if _fp_learning_integration is None:
        _fp_learning_integration = AODSFPLearningIntegration(config)
    
    return _fp_learning_integration

def get_fp_learning_integration() -> Optional[AODSFPLearningIntegration]:
    """Get the global FP learning integration instance."""
    return _fp_learning_integration

def process_finding_with_learning(finding_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to process findings with learning."""
    integration = get_fp_learning_integration()
    if integration:
        return integration.process_finding_with_learning(finding_data)
    return finding_data

def collect_fp_feedback(finding_id: str, is_false_positive: bool, 
                       source: str = 'user', reviewer_id: str = None, 
                       reason: str = None) -> bool:
    """Convenience function to collect feedback."""
    integration = get_fp_learning_integration()
    if integration:
        return integration.collect_feedback(finding_id, is_false_positive, source, reviewer_id, reason)
    return False
