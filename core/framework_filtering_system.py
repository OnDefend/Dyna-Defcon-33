#!/usr/bin/env python3
"""
Modular Framework Filtering System for AODS

This module provides a centralized, extensible framework filtering system
that can be easily extended with new framework-specific filters without
modifying core code.

Consolidates ALL features from:
- core/comprehensive_framework_filter.py
- plugins/enhanced_firebase_integration_analyzer.py

Architecture:
- Central FilterManager coordinates all filtering
- Framework-specific filter modules (plugins)
- Standardized FilterResult interface
- Easy extension through registration system
- Complete vulnerability filtering capabilities
"""

import logging
import os
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import importlib
import inspect

# Import centralized constants
from core.framework_constants.framework_core_constants import CentralizedConstants, FrameworkConstants

logger = logging.getLogger(__name__)

@dataclass
class FilterResult:
    """Standardized result from framework filtering."""
    should_filter: bool
    reason: str
    framework_name: str
    confidence: float
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class FrameworkDetectionResult:
    """Result from framework detection."""
    framework_detected: bool
    framework_name: str
    detection_confidence: float
    detected_services: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.detected_services is None:
            self.detected_services = []
        if self.metadata is None:
            self.metadata = {}

class BaseFrameworkFilter(ABC):
    """Base class for all framework-specific filters."""
    
    def __init__(self, app_package_name: str = None):
        self.app_package_name = app_package_name
        self.logger = logger
    
    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Name of the framework this filter handles."""
        pass
    
    @property
    @abstractmethod
    def priority(self) -> int:
        """Priority of this filter (higher = checked first)."""
        pass
    
    @abstractmethod
    def detect_framework_usage(self, file_path: str) -> FrameworkDetectionResult:
        """Detect if this framework is used in the given file."""
        pass
    
    @abstractmethod
    def should_filter_file(self, file_path: str) -> FilterResult:
        """Determine if the file should be filtered for this framework."""
        pass
    
    @abstractmethod
    def get_excluded_patterns(self) -> Set[str]:
        """Get patterns that should be excluded for this framework."""
        pass
    
    def get_integration_patterns(self) -> Set[str]:
        """Get patterns that indicate app integration (should NOT be filtered)."""
        return set()

class FrameworkFilterManager:
    """
    Central manager for all framework filtering operations.
    Uses centralized constants to eliminate pattern duplication.
    """
    
    def __init__(self, app_package_name: str = None, apk_ctx=None):
        self.app_package_name = app_package_name
        self.apk_ctx = apk_ctx
        self.filters: Dict[str, BaseFrameworkFilter] = {}
        self.logger = logger
        
        # Extract app package from manifest if not provided
        if not self.app_package_name and apk_ctx:
            self.app_package_name = self._extract_app_package_name()
        
        # Auto-discover and register filters
        self._discover_and_register_filters()
        
        if self.app_package_name:
            logger.info(f"🎯 Comprehensive framework filter initialized for app package: {self.app_package_name}")
    
    def _extract_app_package_name(self) -> Optional[str]:
        """
        Extract the main application package name from AndroidManifest.xml.
        Consolidated from comprehensive_framework_filter.py
        """
        try:
            if not self.apk_ctx:
                return None
                
            # Try multiple manifest locations
            manifest_candidates = []
            
            # From APK context
            if hasattr(self.apk_ctx, 'manifest_path') and self.apk_ctx.manifest_path:
                manifest_candidates.append(self.apk_ctx.manifest_path)
            
            if hasattr(self.apk_ctx, 'decompiled_apk_dir') and self.apk_ctx.decompiled_apk_dir:
                manifest_candidates.append(self.apk_ctx.decompiled_apk_dir / "AndroidManifest.xml")
            
            # Common locations
            manifest_candidates.extend([
                "AndroidManifest.xml",
                "/tmp/jadx_decompiled/AndroidManifest.xml"
            ])
            
            # Add glob results
            try:
                glob_results = list(Path("/tmp/jadx_decompiled").glob("**/AndroidManifest.xml"))
                manifest_candidates.extend(glob_results)
            except Exception:
                pass  # Ignore glob errors
            
            manifest_path = None
            for candidate in manifest_candidates:
                if isinstance(candidate, str) and Path(candidate).exists():
                    manifest_path = candidate
                    break
                elif hasattr(candidate, 'exists') and candidate.exists():
                    manifest_path = candidate
                    break
            
            if not manifest_path:
                logger.warning("📄 AndroidManifest.xml not found - using package filtering only")
                return None
            
            # Parse AndroidManifest.xml
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract package name from manifest
            package_name = root.get('package')
            if package_name:
                # Convert to file path format
                package_path = package_name.replace('.', '/')
                logger.info(f"📦 Detected app package: {package_name} -> {package_path}/")
                return package_path
                
        except Exception as e:
            logger.warning(f"⚠️ Failed to extract app package name: {e}")
        
        return None
    
    def _discover_and_register_filters(self):
        """Automatically discover and register all available framework filters."""
        try:
            # Look for framework filter modules in the framework_filters directory
            filters_dir = Path(__file__).parent / "framework_filters"
            if filters_dir.exists():
                for filter_file in filters_dir.glob("*_filter.py"):
                    if filter_file.name.startswith("__"):
                        continue
                    
                    try:
                        module_name = f"core.framework_filters.{filter_file.stem}"
                        module = importlib.import_module(module_name)
                        
                        # Find all BaseFrameworkFilter subclasses in the module
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if (issubclass(obj, BaseFrameworkFilter) and 
                                obj != BaseFrameworkFilter):
                                self.register_filter(obj(self.app_package_name))
                                
                    except Exception as e:
                        self.logger.warning(f"Failed to load filter from {filter_file}: {e}")
            
            # Also register built-in filters
            self._register_builtin_filters()
            
        except Exception as e:
            self.logger.error(f"Failed to discover framework filters: {e}")
    
    def _register_builtin_filters(self):
        """Register built-in framework filters."""
        try:
            # Register built-in filters (for backwards compatibility)
            from core.framework_filters.firebase_filter import FirebaseFrameworkFilter
            from core.framework_filters.android_filter import AndroidFrameworkFilter
            from core.framework_filters.google_services_filter import GoogleServicesFrameworkFilter
            
            builtin_filters = [
                FirebaseFrameworkFilter(self.app_package_name),
                AndroidFrameworkFilter(self.app_package_name),
                GoogleServicesFrameworkFilter(self.app_package_name),
            ]
            
            for filter_instance in builtin_filters:
                self.register_filter(filter_instance)
                
        except ImportError as e:
            self.logger.warning(f"Some built-in filters not available: {e}")
    
    def register_filter(self, filter_instance: BaseFrameworkFilter):
        """Register a framework filter."""
        framework_name = filter_instance.framework_name
        self.filters[framework_name] = filter_instance
        self.logger.debug(f"Registered framework filter: {framework_name}")
    
    def unregister_filter(self, framework_name: str):
        """Unregister a framework filter."""
        if framework_name in self.filters:
            del self.filters[framework_name]
            self.logger.debug(f"Unregistered framework filter: {framework_name}")
    
    def get_registered_frameworks(self) -> List[str]:
        """Get list of all registered framework names."""
        return list(self.filters.keys())
    
    def detect_frameworks_in_file(self, file_path: str) -> Dict[str, FrameworkDetectionResult]:
        """Detect all frameworks used in a file."""
        detections = {}
        
        for framework_name, filter_instance in self.filters.items():
            try:
                detection = filter_instance.detect_framework_usage(file_path)
                if detection.framework_detected:
                    detections[framework_name] = detection
            except Exception as e:
                self.logger.warning(f"Framework detection failed for {framework_name} on {file_path}: {e}")
        
        return detections
    
    def should_filter_file(self, file_path: str) -> Tuple[bool, List[FilterResult]]:
        """
        Determine if a file should be filtered based on all registered filters.
        
        Returns:
            Tuple[bool, List[FilterResult]]: (should_filter, filter_results)
        """
        filter_results = []
        
        # Sort filters by priority (highest first)
        sorted_filters = sorted(self.filters.values(), key=lambda f: f.priority, reverse=True)
        
        for filter_instance in sorted_filters:
            try:
                result = filter_instance.should_filter_file(file_path)
                filter_results.append(result)
                
                # If any filter says to filter, and has high confidence, filter it
                if result.should_filter and result.confidence >= 0.8:
                    self.logger.debug(f"File {file_path} filtered by {result.framework_name}: {result.reason}")
                    return True, filter_results
                    
            except Exception as e:
                self.logger.warning(f"Filtering failed for {filter_instance.framework_name} on {file_path}: {e}")
        
        # If no high-confidence filter decision, check for any filter decision
        for result in filter_results:
            if result.should_filter:
                self.logger.debug(f"File {file_path} filtered by {result.framework_name}: {result.reason}")
                return True, filter_results
        
        return False, filter_results
    
    def is_framework_code(self, file_path: str) -> bool:
        """
        Comprehensive check if a file path represents framework/library code.
        Uses centralized constants to eliminate duplication.
        """
        if not file_path:
            return False
        
        # Use modular filtering system
        should_filter, _ = self.should_filter_file(file_path)
        if should_filter:
            return True
        
        # Fallback: Check against centralized patterns
        normalized_path = file_path.replace('\\', '/').lower()
        
        # Universal framework integration patterns - DON'T filter these
        integration_patterns = CentralizedConstants.get_all_integration_patterns()
        
        for pattern in integration_patterns:
            if pattern in normalized_path:
                logger.debug(f"⚙️ Framework integration file (keeping for analysis): {file_path}")
                return False
        
        # Universal handling for app framework integration code
        if self.app_package_name:
            app_pkg_lower = self.app_package_name.lower()
            if app_pkg_lower in normalized_path:
                # Check if this is framework integration code within the app
                for keyword in FrameworkConstants.FRAMEWORK_INTEGRATION_KEYWORDS:
                    if keyword in normalized_path:
                        logger.debug(f"⚙️ App framework integration code (keeping): {file_path} -> {keyword}")
                        return False
        
        # Check against centralized excluded packages
        excluded_patterns = CentralizedConstants.get_all_excluded_patterns()
        for excluded_pkg in excluded_patterns:
            if excluded_pkg.lower() in normalized_path:
                logger.debug(f"🚫 Framework file (centralized filter): {file_path} -> {excluded_pkg}")
                return True
        
        # If we have app package name, prioritize app code
        if self.app_package_name:
            app_pkg_lower = self.app_package_name.lower()
            
            # If file is clearly in app package, it's NOT framework code
            if app_pkg_lower in normalized_path:
                logger.debug(f"✅ App file (package match): {file_path}")
                return False
            
            # **FIX**: Don't filter AndroidManifest.xml and other critical app files
            critical_app_files = ['androidmanifest.xml', 'strings.xml', 'network_security_config.xml']
            if any(critical_file in normalized_path for critical_file in critical_app_files):
                logger.debug(f"✅ Critical app file (keeping): {file_path}")
                return False
                
            # **FIX**: Only filter if it's CLEARLY a known framework/library path
            known_framework_paths = ['com/google/', 'androidx/', 'android/support/', 'okhttp3/', 'kotlin/', 'kotlinx/']
            if any(framework_path in normalized_path for framework_path in known_framework_paths):
                logger.debug(f"🚫 Framework file (known path): {file_path}")
                return True
        
        return False
    
    def is_app_code(self, file_path: str) -> bool:
        """
        Check if a file path represents application-specific code.
        This is the inverse of is_framework_code() for clarity.
        """
        return not self.is_framework_code(file_path)
    
    def filter_file_list(self, file_paths: List[str]) -> List[str]:
        """
        Filter a list of file paths to only include application code.
        Consolidated from comprehensive_framework_filter.py
        """
        app_files = []
        framework_files = []
        
        for file_path in file_paths:
            if self.is_app_code(file_path):
                app_files.append(file_path)
            else:
                framework_files.append(file_path)
        
        logger.info(f"📊 File filtering results:")
        logger.info(f"   ✅ App files: {len(app_files)}")
        logger.info(f"   🚫 Framework files filtered: {len(framework_files)}")
        
        if len(framework_files) > 0 and len(framework_files) <= 10:
            logger.debug(f"   🚫 Filtered framework files: {framework_files}")
        elif len(framework_files) > 10:
            logger.debug(f"   🚫 Filtered framework files (sample): {framework_files[:10]}...")
        
        return app_files
    
    def get_all_excluded_patterns(self) -> Set[str]:
        """Get all excluded patterns from centralized constants and registered filters."""
        # Use centralized patterns as primary source
        all_patterns = CentralizedConstants.get_all_excluded_patterns()
        
        # Add any additional patterns from filters (for backwards compatibility)
        for filter_instance in self.filters.values():
            try:
                patterns = filter_instance.get_excluded_patterns()
                # Only add patterns not already in centralized constants
                new_patterns = patterns - all_patterns
                if new_patterns:
                    self.logger.debug(f"Adding new patterns from {filter_instance.framework_name}: {new_patterns}")
                    all_patterns.update(new_patterns)
            except Exception as e:
                self.logger.warning(f"Failed to get patterns from {filter_instance.framework_name}: {e}")
        
        return all_patterns
    
    def get_framework_integration_patterns(self, framework_name: str) -> Set[str]:
        """Get integration patterns for a specific framework."""
        # First check centralized constants
        centralized_patterns = CentralizedConstants.get_integration_patterns(framework_name)
        if centralized_patterns:
            return centralized_patterns
        
        # Fallback to filter-specific patterns
        if framework_name in self.filters:
            try:
                return self.filters[framework_name].get_integration_patterns()
            except Exception as e:
                self.logger.warning(f"Failed to get integration patterns for {framework_name}: {e}")
        
        return set()
    
    def is_app_specific_file(self, file_path: str) -> bool:
        """
        Determine if a file is app-specific (should be analyzed).
        
        This is the inverse of filtering - if no frameworks claim it,
        and it's in the app package, it's app-specific.
        """
        should_filter, filter_results = self.should_filter_file(file_path)
        
        if should_filter:
            return False
        
        # Check if file is in app package
        if self.app_package_name:
            normalized_path = file_path.replace('\\', '/').lower()
            app_pkg_path = self.app_package_name.lower()
            if app_pkg_path in normalized_path:
                return True
        
        # Check for common app indicators
        app_indicators = [
            'assets/', 'res/', 'raw/', 'values/', 'xml/',
            'main/', 'debug/', 'release/'
        ]
        
        normalized_path = file_path.replace('\\', '/').lower()
        return any(indicator in normalized_path for indicator in app_indicators)
    
    def filter_vulnerability_results(self, vulnerabilities: List[Dict], apk_ctx=None) -> Dict[str, Any]:
        """
        Filter vulnerability results using all registered framework filters.
        
        This replaces and consolidates the old filter_vulnerability_results function
        from comprehensive_framework_filter.py with enhanced capabilities.
        """
        filtered_vulnerabilities = []
        filtering_stats = {
            'total_input': len(vulnerabilities),
            'filtered_out': 0,
            'kept_for_analysis': 0,
            'framework_breakdown': {},
            'confidence_breakdown': {'high': 0, 'medium': 0, 'low': 0},
            'app_package_name': self.app_package_name,
            'frameworks_detected': list(self.filters.keys()),
            'centralized_patterns_used': True
        }
        
        for vuln in vulnerabilities:
            file_path = vuln.get('file_path', '')
            
            if not file_path:
                filtered_vulnerabilities.append(vuln)
                continue
            
            should_filter, filter_results = self.should_filter_file(file_path)
            
            if should_filter:
                filtering_stats['filtered_out'] += 1
                
                # Track which framework filtered it and confidence
                for result in filter_results:
                    if result.should_filter:
                        framework = result.framework_name
                        if framework not in filtering_stats['framework_breakdown']:
                            filtering_stats['framework_breakdown'][framework] = 0
                        filtering_stats['framework_breakdown'][framework] += 1
                        
                        # Track confidence levels
                        if result.confidence >= 0.8:
                            filtering_stats['confidence_breakdown']['high'] += 1
                        elif result.confidence >= 0.5:
                            filtering_stats['confidence_breakdown']['medium'] += 1
                        else:
                            filtering_stats['confidence_breakdown']['low'] += 1
                        break
            else:
                filtered_vulnerabilities.append(vuln)
                filtering_stats['kept_for_analysis'] += 1
        
        # Additional statistics
        if filtering_stats['total_input'] > 0:
            filtering_stats['filter_percentage'] = round(
                (filtering_stats['filtered_out'] / filtering_stats['total_input']) * 100, 1
            )
        else:
            filtering_stats['filter_percentage'] = 0.0
        
        logger.info(f"🎯 Comprehensive vulnerability filtering results:")
        logger.info(f"   ✅ App vulnerabilities: {filtering_stats['kept_for_analysis']}")
        logger.info(f"   🚫 Framework vulnerabilities filtered: {filtering_stats['filtered_out']} ({filtering_stats['filter_percentage']}%)")
        
        return {
            'filtered_vulnerabilities': filtered_vulnerabilities,
            'filtering_stats': filtering_stats
        }
    
    def get_filter_stats(self) -> dict:
        """
        Get comprehensive statistics about the current filter configuration.
        Enhanced from comprehensive_framework_filter.py
        """
        centralized_stats = CentralizedConstants.get_statistics() if hasattr(CentralizedConstants, 'get_statistics') else {}
        
        return {
            'app_package_name': self.app_package_name,
            'registered_frameworks': list(self.filters.keys()),
            'comprehensive_excluded_packages_count': len(FrameworkConstants.COMPREHENSIVE_EXCLUDED_PACKAGES),
            'total_excluded_patterns': len(self.get_all_excluded_patterns()),
            'centralized_constants_active': True,
            'centralized_stats': centralized_stats,
            'filter_strategies': [
                'Modular Framework Filters',
                'Centralized Pattern Constants',
                'App Package Prioritization' if self.app_package_name else 'Package Detection Failed',
                'Universal Integration Pattern Detection',
                'Priority-based Filtering'
            ],
            'capabilities': [
                'Framework Detection',
                'Smart Integration Filtering',
                'Vulnerability Result Filtering',
                'File List Filtering',
                'Confidence-based Decisions',
                'Detailed Statistics',
                'Centralized Pattern Management'
            ]
        }
    
    def detect_firebase_integration(self, apk_ctx) -> bool:
        """Detect if Firebase integration exists in the APK."""
        try:
            # Check if Firebase filter is available and detects integration
            firebase_filter = self.filters.get('firebase')
            if firebase_filter:
                # Check for Firebase-specific files and patterns
                firebase_detection = firebase_filter.detect_framework_integration(apk_ctx)
                return firebase_detection.integration_detected
            
            # Fallback: Basic Firebase detection
            if hasattr(apk_ctx, 'apk_path'):
                # Basic check for Firebase indicators
                return 'firebase' in str(apk_ctx.apk_path).lower()
                
            return False
        except Exception as e:
            logger.warning(f"Firebase detection failed: {e}")
            return False

# Convenience function for backwards compatibility
def create_framework_filter_manager(app_package_name: str = None, apk_ctx=None) -> FrameworkFilterManager:
    """Create and return a configured FrameworkFilterManager."""
    return FrameworkFilterManager(app_package_name, apk_ctx)

# Global instance for backwards compatibility
_global_filter_manager = None

def get_global_filter_manager(app_package_name: str = None, apk_ctx=None) -> FrameworkFilterManager:
    """Get or create the global filter manager instance."""
    global _global_filter_manager
    
    if (_global_filter_manager is None or 
        (app_package_name and _global_filter_manager.app_package_name != app_package_name) or
        (apk_ctx and _global_filter_manager.apk_ctx != apk_ctx)):
        _global_filter_manager = FrameworkFilterManager(app_package_name, apk_ctx)
    
    return _global_filter_manager

# Legacy function for backwards compatibility with comprehensive_framework_filter.py
def filter_vulnerability_results(vulnerabilities: List[Dict], apk_ctx=None) -> Dict[str, Any]:
    """
    Legacy function - use FrameworkFilterManager.filter_vulnerability_results instead.
    Maintains compatibility with comprehensive_framework_filter.py
    """
    app_package_name = getattr(apk_ctx, 'package_name', None)
    manager = get_global_filter_manager(app_package_name, apk_ctx)
    return manager.filter_vulnerability_results(vulnerabilities, apk_ctx)

# Legacy functions for backwards compatibility with comprehensive_framework_filter.py
def get_framework_filter(apk_ctx=None) -> FrameworkFilterManager:
    """Legacy function - returns FrameworkFilterManager for compatibility."""
    app_package_name = getattr(apk_ctx, 'package_name', None)
    return get_global_filter_manager(app_package_name, apk_ctx)

def should_scan_file(file_path: str, apk_ctx=None) -> bool:
    """
    Legacy function for comprehensive_framework_filter.py compatibility.
    Central function to determine if a file should be scanned.
    """
    app_package_name = getattr(apk_ctx, 'package_name', None)
    manager = get_global_filter_manager(app_package_name, apk_ctx)
    return manager.is_app_code(file_path)

if __name__ == "__main__":
    # Test the comprehensive modular filtering system with centralized constants
    manager = FrameworkFilterManager("com.example.testapp")
    
    print("🔧 Comprehensive Modular Framework Filtering System (Centralized Constants)")
    print(f"📋 Registered frameworks: {manager.get_registered_frameworks()}")
    print(f"🎯 Total excluded patterns: {len(manager.get_all_excluded_patterns())}")
    print(f"📊 Filter statistics: {manager.get_filter_stats()}")
    
    # Test filtering
    test_files = [
        "com/google/firebase/internal/AuthService.java",
        "com/example/testapp/firebase/FirebaseManager.java",
        "assets/google-services.json",
        "com/example/testapp/MainActivity.java"
    ]
    
    for test_file in test_files:
        should_filter, results = manager.should_filter_file(test_file)
        status = "FILTER" if should_filter else "ANALYZE"
        print(f"📁 {test_file} -> {status}")