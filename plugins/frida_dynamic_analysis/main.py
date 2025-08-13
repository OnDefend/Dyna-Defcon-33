#!/usr/bin/env python3
"""
Main entry point for Frida Dynamic Analysis Plugin.
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

def run_plugin(apk_path: str, output_dir: str = ".", options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Main plugin entry point for Frida dynamic analysis.
    
    Args:
        apk_path: Path to the APK file to analyze OR APKContext object
        output_dir: Directory to save analysis results
        options: Optional configuration options
    
    Returns:
        Dict containing analysis results
    """
    try:
        logger.info(f"Starting Frida dynamic analysis for {apk_path}")
        
        # Import analyzer here to avoid circular imports
        from .enhanced_frida_analyzer import EnhancedFridaDynamicAnalyzer
        
        # Handle both APKContext objects and string paths
        apk_ctx = None
        package_name = "unknown.package"  # Default fallback
        
        if hasattr(apk_path, 'package_name'):
            # It's an APKContext object
            apk_ctx = apk_path
            package_name = apk_path.package_name or "unknown.package"
            logger.info(f"Received APKContext for package: {package_name}")
        else:
            # It's a string path - try to extract package name from options first
            if isinstance(apk_path, str):
                # Check if package name is provided in options
                if options and 'package_name' in options and options['package_name']:
                    package_name = options['package_name']
                    logger.info(f"Using package name from options: {package_name}")
                else:
                    # Fallback: try to extract from APK path
                    from pathlib import Path
                    apk_name = Path(apk_path).stem
                    package_name = f"com.example.{apk_name}"
                    logger.warning(f"No package name provided, extracted from APK path: {package_name}")
        
        # Ensure we never have an empty or None package name
        if not package_name or package_name in ["", "None", "null"]:
            package_name = "unknown.package"
            logger.warning("Package name is empty or invalid, using fallback: unknown.package")
        
        # Initialize analyzer with correct parameters
        config = options or {}
        analyzer = EnhancedFridaDynamicAnalyzer(package_name, config)
        
        # Run analysis - pass APK context if available for full analysis
        if apk_ctx is not None:
            logger.info("Performing full dynamic analysis with APK context")
            results = analyzer.analyze(apk_ctx=apk_ctx)
        else:
            logger.info("Performing basic dynamic analysis without APK context")
            results = analyzer.analyze()
        
        logger.info("Frida dynamic analysis completed successfully")
        return results
        
    except Exception as e:
        logger.error(f"Frida dynamic analysis failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "findings": []
        }

def run(apk_path: str, output_dir: str = ".", options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Alias for run_plugin for backward compatibility.
    """
    return run_plugin(apk_path, output_dir, options) 