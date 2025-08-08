#!/usr/bin/env python3
"""
AODS ML-Enhanced Confidence Scoring Integration
Integrates the ML confidence scoring system with AODS components
"""

import logging
import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AODSMLConfidenceIntegration:
    """Integration layer for ML-enhanced confidence scoring."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.confidence_config = config.get('ml_enhanced_confidence', {})
        self.integration_config = config.get('confidence_integration', {})
        self.confidence_manager = None
        
        # Initialize if enabled
        if self.confidence_config.get('enabled', False):
            self._initialize_confidence_system()
    
    def _initialize_confidence_system(self):
        """Initialize the ML-enhanced confidence scoring system."""
        try:
            from core.ml_enhanced_confidence_scorer import ConfidenceIntegrationManager
            
            self.confidence_manager = ConfidenceIntegrationManager(self.config)
            
            logger.info("✅ ML-enhanced confidence scoring system initialized")
            
        except ImportError as e:
            logger.warning(f"⚠️ ML confidence scoring system not available: {e}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize ML confidence scoring system: {e}")
    
    def process_finding_with_confidence_enhancement(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a finding with ML-enhanced confidence scoring."""
        if not self.confidence_manager:
            return finding_data
        
        try:
            # Enhance confidence with ML analysis
            enhanced_finding = self.confidence_manager.enhance_finding_confidence(finding_data)
            
            # Add integration metadata
            enhanced_finding['confidence_enhancement_metadata'] = {
                'ml_enhanced': True,
                'enhancement_timestamp': datetime.now().isoformat(),
                'uncertainty_quantified': True,
                'ensemble_aggregated': True,
                'evidence_analyzed': True
            }
            
            # Log confidence enhancement details
            original_confidence = finding_data.get('confidence_score', 0.5)
            enhanced_confidence = enhanced_finding.get('confidence_score', 0.5)
            
            if abs(enhanced_confidence - original_confidence) > 0.1:
                logger.debug(f"Confidence enhanced: {original_confidence:.2f} → {enhanced_confidence:.2f}")
            
            return enhanced_finding
            
        except Exception as e:
            logger.error(f"Error in confidence enhancement: {e}")
            return finding_data
    
    def record_finding_outcome(self, finding_id: str, finding_data: Dict[str, Any], 
                             is_true_positive: bool) -> bool:
        """Record the outcome of a finding for confidence calibration."""
        if not self.confidence_manager:
            return False
        
        try:
            # Record outcome for calibration
            self.confidence_manager.record_finding_outcome(finding_id, finding_data, is_true_positive)
            
            logger.debug(f"Recorded outcome for {finding_id}: {'TP' if is_true_positive else 'FP'}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to record finding outcome: {e}")
            return False
    
    def get_confidence_statistics(self) -> Dict[str, Any]:
        """Get confidence scoring statistics."""
        if not self.confidence_manager:
            return {'status': 'not_available'}
        
        try:
            stats = self.confidence_manager.get_confidence_statistics()
            stats['status'] = 'active'
            stats['ml_enhanced'] = True
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get confidence statistics: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def validate_confidence_integration(self) -> Dict[str, bool]:
        """Validate the confidence integration system."""
        validation_results = {
            'confidence_manager_initialized': self.confidence_manager is not None,
            'config_loaded': bool(self.confidence_config),
            'integration_config_loaded': bool(self.integration_config),
            'ml_libraries_available': False,
            'calibration_enabled': self.confidence_config.get('calibration', {}).get('enabled', False)
        }
        
        # Test ML libraries
        try:
            import sklearn
            import numpy as np
            validation_results['ml_libraries_available'] = True
        except ImportError:
            pass
        
        return validation_results

# Global instance for easy access
_ml_confidence_integration = None

def initialize_ml_confidence_integration(config: Dict[str, Any]) -> Optional[AODSMLConfidenceIntegration]:
    """Initialize global ML confidence integration."""
    global _ml_confidence_integration
    
    if _ml_confidence_integration is None:
        _ml_confidence_integration = AODSMLConfidenceIntegration(config)
    
    return _ml_confidence_integration

def get_ml_confidence_integration() -> Optional[AODSMLConfidenceIntegration]:
    """Get the global ML confidence integration instance."""
    return _ml_confidence_integration

def enhance_finding_confidence(finding_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to enhance finding confidence."""
    integration = get_ml_confidence_integration()
    if integration:
        return integration.process_finding_with_confidence_enhancement(finding_data)
    return finding_data

def record_finding_outcome(finding_id: str, finding_data: Dict[str, Any], is_true_positive: bool) -> bool:
    """Convenience function to record finding outcomes."""
    integration = get_ml_confidence_integration()
    if integration:
        return integration.record_finding_outcome(finding_id, finding_data, is_true_positive)
    return False

def get_confidence_statistics() -> Dict[str, Any]:
    """Convenience function to get confidence statistics."""
    integration = get_ml_confidence_integration()
    if integration:
        return integration.get_confidence_statistics()
    return {'status': 'not_available'}
