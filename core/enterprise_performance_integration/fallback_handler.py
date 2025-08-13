#!/usr/bin/env python3
"""
Enterprise Performance Integration - Fallback Handler

Graceful degradation and fallback processing when optimization frameworks
are unavailable or encounter errors.
"""

import logging
from typing import Dict, List, Any


class FallbackHandler:
    """
    Handles graceful fallback scenarios when optimization frameworks
    are unavailable or encounter errors during processing.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def create_fallback_result(self, apk_path: str, findings: List[Dict[str, Any]], 
                              app_context: Dict[str, Any], error_msg: str) -> Dict[str, Any]:
        """Create fallback result when optimization fails."""
        self.logger.warning(f"Creating fallback result due to: {error_msg}")
        
        return {
            'status': 'fallback',
            'optimization_applied': False,
            'enterprise_mode': False,
            'error': error_msg,
            'original_findings': len(findings),
            'final_findings': len(findings),
            'reduction_percentage': 0,
            'analysis_time_seconds': 0,
            'apk_path': apk_path,
            'fallback_mode': True,
            'detailed_results': self.process_findings_fallback(findings, app_context)
        }
    
    def process_findings_fallback(self, findings: List[Dict[str, Any]], 
                                app_context: Dict[str, Any]) -> Dict[str, Any]:
        """Basic fallback processing when all optimization frameworks fail."""
        self.logger.info("Using basic fallback processing")
        
        return {
            'final_findings': findings,
            'total_findings': len(findings),
            'accuracy_metrics': {
                'overall_reduction_percentage': 0,
                'fallback_mode': True
            },
            'processing_metrics': {
                'total_time_ms': 0,
                'fallback_processing': True
            },
            'fallback_mode': True,
            'optimization_applied': False,
            'message': 'Optimization frameworks unavailable - using basic processing'
        }
    
    def validate_optimization_result(self, result: Dict[str, Any]) -> bool:
        """Validate that optimization result contains required fields."""
        required_fields = ['final_findings', 'total_findings']
        
        for field in required_fields:
            if field not in result:
                self.logger.warning(f"Optimization result missing required field: {field}")
                return False
        
        return True
    
    def enhance_fallback_result(self, basic_result: Dict[str, Any], 
                               available_frameworks: List[str]) -> Dict[str, Any]:
        """Enhance fallback result with information about available frameworks."""
        enhanced_result = basic_result.copy()
        
        enhanced_result.update({
            'available_frameworks': available_frameworks,
            'framework_count': len(available_frameworks),
            'degradation_level': self._calculate_degradation_level(available_frameworks)
        })
        
        return enhanced_result
    
    def _calculate_degradation_level(self, available_frameworks: List[str]) -> str:
        """Calculate the level of feature degradation based on available frameworks."""
        total_frameworks = 4  # Expected total frameworks
        available_count = len(available_frameworks)
        
        if available_count == 0:
            return 'complete'
        elif available_count < total_frameworks * 0.25:
            return 'severe'
        elif available_count < total_frameworks * 0.5:
            return 'moderate'
        elif available_count < total_frameworks * 0.75:
            return 'minor'
        else:
            return 'minimal' 
 
 