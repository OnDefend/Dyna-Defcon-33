#!/usr/bin/env python3
"""
MIGRATION NOTICE: This file has been deprecated and replaced by the modular system.

This file was moved to deprecated/ because all functionality has been 
consolidated into the new modular framework filtering system:

NEW SYSTEM:
- core/framework_filtering_system.py (Central manager)
- core/framework_constants.py (Centralized constants)
- core/framework_filters/*.py (Modular filters)

MIGRATION:
Replace imports:
  OLD: from core.comprehensive_framework_filter import get_framework_filter
  NEW: from core.framework_filtering_system import get_framework_filter

All legacy functions are available for backwards compatibility.

For new code, use:
  from core.framework_filtering_system import FrameworkFilterManager
  manager = FrameworkFilterManager(app_package_name, apk_ctx)
"""

# Legacy imports for backwards compatibility
from core.framework_filtering_system import (
    filter_vulnerability_results,
    get_framework_filter, 
    should_scan_file,
    FrameworkFilterManager
)

# Alias for legacy compatibility
ComprehensiveFrameworkFilter = FrameworkFilterManager

# Legacy function aliases
def get_framework_filter_legacy(apk_ctx=None):
    return get_framework_filter(apk_ctx)

# Export all legacy functions for backwards compatibility
__all__ = [
    'filter_vulnerability_results',
    'get_framework_filter', 
    'should_scan_file',
    'ComprehensiveFrameworkFilter',
    'FrameworkFilterManager'
]
