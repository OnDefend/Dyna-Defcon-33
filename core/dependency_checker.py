"""
Dependency Checker for AODS

This module provides dependency checking and graceful degradation capabilities.
"""

import logging
import importlib
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class DependencyChecker:
    """Check for optional dependencies and provide graceful degradation."""
    
    def __init__(self):
        """Initialize dependency checker."""
        self.dependency_status = {}
        self.fallback_available = {}
    
    def check_ml_dependencies(self) -> Dict[str, bool]:
        """Check for ML-related dependencies."""
        ml_deps = {
            'xgboost': False,
            'textdistance': False,
            'sklearn': False,
            'numpy': False,
            'pandas': False
        }
        
        for dep in ml_deps:
            try:
                importlib.import_module(dep)
                ml_deps[dep] = True
                logger.debug(f"✅ {dep}: Available")
            except ImportError:
                logger.warning(f"⚠️ {dep}: Not available")
        
        self.dependency_status.update(ml_deps)
        return ml_deps
    
    def check_semantic_dependencies(self) -> Dict[str, bool]:
        """Check for semantic analysis dependencies."""
        semantic_deps = {
            'ast': True,  # Built-in
            'tree_sitter': False,
            'javalang': False
        }
        
        for dep in semantic_deps:
            if dep == 'ast':
                continue  # Skip built-in
                
            try:
                importlib.import_module(dep)
                semantic_deps[dep] = True
                logger.debug(f"✅ {dep}: Available")
            except ImportError:
                logger.warning(f"⚠️ {dep}: Not available")
        
        self.dependency_status.update(semantic_deps)
        return semantic_deps
    
    def get_dependency_status(self) -> Dict[str, bool]:
        """Get overall dependency status."""
        return self.dependency_status.copy()
    
    def suggest_installations(self) -> List[str]:
        """Suggest commands to install missing dependencies."""
        suggestions = []
        
        missing_deps = [dep for dep, available in self.dependency_status.items() if not available]
        
        if missing_deps:
            pip_install = f"pip install {' '.join(missing_deps)}"
            suggestions.append(pip_install)
        
        return suggestions

# Global dependency checker instance
dependency_checker = DependencyChecker()
