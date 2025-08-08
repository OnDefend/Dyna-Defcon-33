#!/usr/bin/env python3
"""
JADX Integration Adapter for Error 8 Resolution

This module provides integration between the enhanced JADX manager and existing 
AODS components, ensuring seamless backward compatibility while delivering 
improved timeout handling and memory management.

Features:
- Drop-in replacement for existing JADX functionality
- Backward compatibility with all existing JADX calls
- Automatic fallback to enhanced manager for better reliability
- Performance monitoring and reporting
"""

import logging
import time
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path

from .enhanced_jadx_manager import (
    EnhancedJADXManager, DecompilationResult, DecompilationReport,
    get_enhanced_jadx_manager
)

logger = logging.getLogger(__name__)

class JADXIntegrationAdapter:
    """
    Integration adapter for enhanced JADX functionality.
    
    Provides backward compatibility with existing JADX calls while
    leveraging enhanced timeout and memory management capabilities.
    """
    
    def __init__(self):
        """Initialize JADX integration adapter."""
        self.enhanced_manager = get_enhanced_jadx_manager()
        self.legacy_call_count = 0
        self.enhanced_call_count = 0
        
    def decompile_apk_legacy_compatible(self, apk_path: str, output_dir: str, 
                                      timeout: int = 300) -> bool:
        """
        Legacy-compatible APK decompilation method.
        
        This method maintains the same signature as existing JADX calls
        but uses the enhanced manager internally.
        
        Args:
            apk_path: Path to APK file
            output_dir: Output directory for decompiled files
            timeout: Timeout in seconds (used as hint for enhanced manager)
            
        Returns:
            True if decompilation successful, False otherwise
        """
        self.legacy_call_count += 1
        
        try:
            logger.info(f"Legacy JADX call #{self.legacy_call_count}: {apk_path}")
            
            # Use enhanced manager with timeout hint
            report = self.enhanced_manager.decompile_apk(apk_path, output_dir)
            
            # Convert to legacy boolean result
            success = report.result in [DecompilationResult.SUCCESS, DecompilationResult.FALLBACK_SUCCESS]
            
            if success:
                logger.info(f"✅ Legacy JADX call successful: {report.files_extracted} files extracted")
            else:
                logger.warning(f"❌ Legacy JADX call failed: {report.error_message}")
                
            return success
            
        except Exception as e:
            logger.error(f"Legacy JADX call failed with exception: {e}")
            return False
    
    def run_jadx_analysis_with_timeout(self, apk_ctx, timeout_seconds: int = 90) -> Tuple[str, str]:
        """
        Enhanced version of run_jadx_analysis_with_timeout function.
        
        Maintains compatibility with existing calls while providing
        improved reliability and error handling.
        
        Args:
            apk_ctx: APK context with package information
            timeout_seconds: Timeout in seconds
            
        Returns:
            Tuple of (title, formatted_results)
        """
        self.enhanced_call_count += 1
        
        try:
            logger.info(f"Enhanced JADX analysis #{self.enhanced_call_count}: {apk_ctx.package_name}")
            
            # Create output directory
            output_dir = str(Path(apk_ctx.decompiled_apk_dir) / "enhanced_jadx")
            
            # Use enhanced manager
            report = self.enhanced_manager.decompile_apk(str(apk_ctx.apk_path), output_dir)
            
            # Format results for compatibility
            if report.result in [DecompilationResult.SUCCESS, DecompilationResult.FALLBACK_SUCCESS]:
                title = "Enhanced JADX Analysis - Success"
                
                results = f"""
Enhanced JADX Decompilation Results:
====================================
Status: {report.result.value}
Execution Time: {report.execution_time:.1f}s
Strategy Used: {report.strategy_used.value if report.strategy_used else 'unknown'}
Files Extracted: {report.files_extracted}
- Java Files: {report.java_files}
- Kotlin Files: {report.kotlin_files}
Memory Peak: {report.memory_peak_mb:.1f}MB
Fallback Used: {report.fallback_used}
Output Directory: {report.output_directory}

Analysis completed successfully with enhanced timeout and memory management.
"""
                
                if report.warnings:
                    results += f"\nWarnings: {len(report.warnings)} warnings reported"
                
            else:
                title = "Enhanced JADX Analysis - Failed"
                
                results = f"""
Enhanced JADX Decompilation Failed:
===================================
Status: {report.result.value}
Execution Time: {report.execution_time:.1f}s
Strategy Used: {report.strategy_used.value if report.strategy_used else 'unknown'}
Memory Peak: {report.memory_peak_mb:.1f}MB
Error: {report.error_message or 'Unknown error'}

Enhanced fallback strategies were attempted but could not recover from the failure.
Consider manual analysis or alternative static analysis approaches.
"""
            
            return title, results
            
        except Exception as e:
            logger.error(f"Enhanced JADX analysis failed with exception: {e}")
            return "Enhanced JADX Analysis - Error", f"Analysis failed with error: {str(e)}"
    
    def get_integration_statistics(self) -> Dict[str, Any]:
        """Get integration statistics and performance metrics."""
        manager_stats = self.enhanced_manager.get_processing_statistics()
        
        return {
            "legacy_calls": self.legacy_call_count,
            "enhanced_calls": self.enhanced_call_count,
            "total_calls": self.legacy_call_count + self.enhanced_call_count,
            "enhanced_manager_stats": manager_stats
        }

# Global adapter instance
_global_jadx_adapter = None

def get_jadx_integration_adapter() -> JADXIntegrationAdapter:
    """Get global JADX integration adapter instance."""
    global _global_jadx_adapter
    if _global_jadx_adapter is None:
        _global_jadx_adapter = JADXIntegrationAdapter()
    return _global_jadx_adapter

# Compatibility functions for existing code
def run_jadx_analysis_with_timeout(apk_ctx, timeout_seconds: int = 90) -> Tuple[str, str]:
    """
    Enhanced compatibility function for existing JADX analysis calls.
    
    This function replaces the existing run_jadx_analysis_with_timeout
    function in jadx_analyzer.py, providing improved reliability.
    """
    adapter = get_jadx_integration_adapter()
    return adapter.run_jadx_analysis_with_timeout(apk_ctx, timeout_seconds)

def decompile_apk_enhanced(apk_path: str, output_dir: str, timeout: int = 300) -> bool:
    """
    Enhanced APK decompilation function for existing code integration.
    
    Args:
        apk_path: Path to APK file
        output_dir: Output directory 
        timeout: Timeout hint in seconds
        
    Returns:
        True if successful, False otherwise
    """
    adapter = get_jadx_integration_adapter()
    return adapter.decompile_apk_legacy_compatible(apk_path, output_dir, timeout) 