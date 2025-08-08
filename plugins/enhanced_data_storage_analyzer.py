#!/usr/bin/env python3
"""
Enhanced Data Storage Analyzer Plugin

This plugin analyzes data storage security in Android applications.
"""

import logging
from typing import Tuple, Union
from rich.text import Text

# Import the modular implementation from the subdirectory using absolute imports
from plugins.enhanced_data_storage_modular import run_plugin as modular_run_plugin
from plugins.enhanced_data_storage_modular import run as modular_run
from plugins.enhanced_data_storage_modular import get_enhanced_data_storage_analyzer

# Initialize logger
logger = logging.getLogger(__name__)

def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Main plugin entry point - redirects to modular implementation.
    
    Maintains 100% backward compatibility with the original monolithic implementation
    while leveraging the new modular architecture for improved maintainability,
    performance, and professional confidence calculation.
    
    Args:
        apk_ctx: APK analysis context containing APK information and file paths
        
    Returns:
        Tuple[str, Union[str, Text]]: (plugin_name, formatted_results)
        - plugin_name: "Enhanced Data Storage Analysis"
        - formatted_results: Rich Text object with color-coded analysis results
    """
    try:
        logger.info("Enhanced Data Storage Analyzer: Redirecting to modular implementation")
        return modular_run_plugin(apk_ctx)
    except Exception as e:
        logger.error(f"Enhanced Data Storage Analyzer redirection failed: {e}")
        # Fallback error message maintaining original interface
        error_text = Text("Enhanced Data Storage Analysis failed", style="bold red")
        error_text.append(f"\nError: {str(e)}", style="red")
        return "Enhanced Data Storage Analysis", error_text

def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Alternative entry point - redirects to modular implementation.
    
    Provides backward compatibility for any code that might call run() directly.
    
    Args:
        apk_ctx: APK analysis context
        
    Returns:
        Tuple[str, Union[str, Text]]: Same as run_plugin()
    """
    return modular_run(apk_ctx)

# Export the analyzer class for direct instantiation if needed
EnhancedDataStorageAnalyzer = get_enhanced_data_storage_analyzer

# Maintain compatibility with any direct imports
__all__ = ['run_plugin', 'run', 'EnhancedDataStorageAnalyzer'] 
 
 
 