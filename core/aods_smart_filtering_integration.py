#!/usr/bin/env python3
"""
AODS Smart Filtering Integration

Main integration point that connects smart filtering improvements to the AODS scan pipeline.
Ensures all JADX timeout optimizations and false positive reductions are properly applied.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

def integrate_smart_filtering_into_aods_pipeline(findings: List[Dict[str, Any]], 
                                               scan_context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main integration function that applies all smart filtering improvements to AODS scans.
    
    Args:
        findings: List of vulnerability findings from plugins
        scan_context: Scan context with APK info, package name, etc.
        
    Returns:
        Dictionary with processed findings and integration statistics
    """
    
    logger.info("🔧 Applying AODS Smart Filtering Integration")
    
    try:
        # Extract context information
        package_name = scan_context.get('package_name', '')
        apk_path = scan_context.get('apk_path', '')
        
        # Step 1: Apply vulnerable app detection and coordination
        from core.vulnerable_app_coordinator import vulnerable_app_coordinator
        
        app_context = {
            'package_name': package_name,
            'apk_path': apk_path
        }
        
        # Get vulnerable app processing override
        override_result = vulnerable_app_coordinator.get_vulnerable_app_override(findings, app_context)
        
        if override_result.get('override_active', False):
            # Vulnerable app detected - use smart filtering
            filtered_findings = override_result.get('filtered_findings', findings)
            
            integration_stats = {
                'integration_applied': True,
                'app_type': override_result['app_type'],
                'original_count': override_result['original_count'],
                'final_count': override_result['final_count'],
                'reduction_percentage': override_result['reduction_percentage'],
                'smart_filtering_applied': override_result.get('smart_filtering_applied', False),
                'strategy': 'vulnerable_app_smart_filtering'
            }
            
            logger.info(f"✅ Smart filtering applied for {override_result['app_type']}:")
            logger.info(f"   Original: {override_result['original_count']} findings")
            logger.info(f"   Final: {override_result['final_count']} findings")
            logger.info(f"   Reduction: {override_result['reduction_percentage']:.1f}%")
            
        else:
            # Production app - apply standard smart filtering
            from core.smart_filtering_integration import apply_smart_filtering_for_vulnerable_apps
            
            result = apply_smart_filtering_for_vulnerable_apps(findings, package_name)
            filtered_findings = result['filtered_findings']
            
            integration_stats = {
                'integration_applied': True,
                'app_type': 'production_app',
                'original_count': result['original_count'],
                'final_count': result['kept_count'],
                'reduction_percentage': result['false_positive_rate'],
                'smart_filtering_applied': True,
                'strategy': result['filtering_strategy']
            }
            
            logger.info(f"✅ Smart filtering applied for production app:")
            logger.info(f"   Original: {result['original_count']} findings")
            logger.info(f"   Kept: {result['kept_count']} findings")
            logger.info(f"   FP Rate: {result['false_positive_rate']:.1f}%")
        
        return {
            'filtered_findings': filtered_findings,  # ✅ Fixed key name
            'processed_findings': filtered_findings,  # Keep backward compatibility
            'integration_stats': integration_stats,
            'success': True
        }
        
    except Exception as e:
        logger.warning(f"Smart filtering integration failed: {e}")
        
        # Fallback: return original findings
        return {
            'filtered_findings': findings,  # ✅ Fixed key name
            'processed_findings': findings,  # Keep backward compatibility
            'integration_stats': {
                'integration_applied': False,
                'error': str(e),
                'strategy': 'fallback_no_filtering'
            },
            'success': False
        }

def ensure_jadx_optimizations_active():
    """Ensure JADX timeout optimizations are properly loaded and active."""
    
    try:
        from core.jadx_timeout_optimizer import get_jadx_timeout_optimizer
        
        optimizer = get_jadx_timeout_optimizer()
        logger.info("✅ JADX Timeout Optimizer: Active and functional")
        
        # Test optimization with sample APK (generic example)
        timeout = optimizer.calculate_optimal_timeout("sample_app.apk", ["crypto_analysis"])
        logger.info(f"   Sample timeout calculation: {timeout}s")
        
        return True
        
    except Exception as e:
        logger.warning(f"JADX optimizations not fully active: {e}")
        return False

def validate_integration_health() -> Dict[str, Any]:
    """Validate that all integration components are healthy and functional."""
    
    health_status = {
        'overall_health': 'unknown',
        'components': {},
        'recommendations': []
    }
    
    # Check JADX optimizations
    try:
        from core.jadx_timeout_optimizer import get_jadx_timeout_optimizer
        get_jadx_timeout_optimizer()
        health_status['components']['jadx_optimizer'] = 'healthy'
    except Exception as e:
        health_status['components']['jadx_optimizer'] = f'error: {e}'
        health_status['recommendations'].append('Fix JADX timeout optimizer')
    
    # Check vulnerable app coordination
    try:
        from core.vulnerable_app_coordinator import vulnerable_app_coordinator
        # Test detection
        test_context = {'package_name': 'test.app', 'apk_path': '/test/path'}
        vulnerable_app_coordinator.detect_vulnerable_app(test_context)
        health_status['components']['vulnerable_app_coordinator'] = 'healthy'
    except Exception as e:
        health_status['components']['vulnerable_app_coordinator'] = f'error: {e}'
        health_status['recommendations'].append('Fix vulnerable app coordinator')
    
    # Check smart filtering
    try:
        from core.smart_filtering_integration import apply_smart_filtering_for_vulnerable_apps
        # Test with minimal input
        apply_smart_filtering_for_vulnerable_apps([], 'test.package')
        health_status['components']['smart_filtering'] = 'healthy'
    except Exception as e:
        health_status['components']['smart_filtering'] = f'error: {e}'
        health_status['recommendations'].append('Fix smart filtering integration')
    
    # Check framework filter
    try:
        from core.optimized_framework_filter import OptimizedFrameworkFilter
        OptimizedFrameworkFilter()
        health_status['components']['framework_filter'] = 'healthy'
    except Exception as e:
        health_status['components']['framework_filter'] = f'error: {e}'
        health_status['recommendations'].append('Fix optimized framework filter')
    
    # Determine overall health
    healthy_components = sum(1 for status in health_status['components'].values() if status == 'healthy')
    total_components = len(health_status['components'])
    
    if healthy_components == total_components:
        health_status['overall_health'] = 'excellent'
    elif healthy_components >= total_components * 0.75:
        health_status['overall_health'] = 'good'
    elif healthy_components >= total_components * 0.5:
        health_status['overall_health'] = 'fair'
    else:
        health_status['overall_health'] = 'poor'
    
    logger.info(f"🏥 Integration Health Check: {health_status['overall_health'].upper()}")
    logger.info(f"   Healthy components: {healthy_components}/{total_components}")
    
    return health_status

# Main integration function that can be called from dyna.py
def apply_aods_smart_improvements(findings: List[Dict[str, Any]], 
                                scan_context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Main function to apply all AODS smart improvements.
    
    This can be called from the main AODS scan pipeline to apply:
    - JADX timeout optimizations
    - Smart false positive filtering  
    - Vulnerable app detection and coordination
    
    Args:
        findings: Raw vulnerability findings
        scan_context: Context with APK and scan information
        
    Returns:
        Processed findings with smart filtering applied
    """
    
    # Ensure JADX optimizations are active
    ensure_jadx_optimizations_active()
    
    # Apply smart filtering integration
    result = integrate_smart_filtering_into_aods_pipeline(findings, scan_context)
    
    if result['success']:
        return result['processed_findings']
    else:
        logger.warning("Smart filtering failed - returning original findings")
        return findings 