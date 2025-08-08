#!/usr/bin/env python3
"""
Firebase Framework Filter

Handles all Firebase-specific filtering logic using centralized constants.
ELIMINATES DUPLICATION: Uses core.framework_constants for all patterns.

Handles:
- Firebase library internals filtering
- Firebase integration code detection
- Firebase configuration file handling
- Smart Firebase filtering (filter internals, keep integration)
- App package detection and AndroidManifest.xml parsing
- Enhanced Firebase service detection
"""

import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Set, Optional
from core.framework_filtering_system import BaseFrameworkFilter, FilterResult, FrameworkDetectionResult

# Import centralized constants
from core.framework_constants.firebase_constants import FirebaseConstants
from core.framework_constants.framework_core_constants import CentralizedConstants

class FirebaseFrameworkFilter(BaseFrameworkFilter):
    """
    Comprehensive Firebase framework filter using centralized constants.
    ELIMINATES DUPLICATION: All patterns come from core.framework_constants.
    """
    
    def __init__(self, app_package_name: str = None):
        super().__init__(app_package_name)
        self.manifest_app_package = self._extract_app_package_from_manifest()
        # Use extracted package if provided package is None
        if not self.app_package_name and self.manifest_app_package:
            self.app_package_name = self.manifest_app_package
    
    @property
    def framework_name(self) -> str:
        return FirebaseConstants.FRAMEWORK_NAME
    
    @property
    def priority(self) -> int:
        return 90  # High priority for Firebase
    
    def _extract_app_package_from_manifest(self) -> Optional[str]:
        """
        Extract app package name from AndroidManifest.xml.
        Consolidated from comprehensive_framework_filter.py
        """
        try:
            # Try common manifest locations
            manifest_paths = [
                "AndroidManifest.xml",
                "/tmp/jadx_decompiled/AndroidManifest.xml",
                Path("/tmp/jadx_decompiled").glob("**/AndroidManifest.xml")
            ]
            
            manifest_path = None
            for path in manifest_paths:
                if isinstance(path, str) and Path(path).exists():
                    manifest_path = path
                    break
                elif hasattr(path, '__iter__'):  # glob result
                    try:
                        manifest_path = next(path)
                        break
                    except StopIteration:
                        continue
            
            if not manifest_path:
                return None
            
            # Parse AndroidManifest.xml
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract package name
            package_name = root.get('package')
            if package_name:
                # Convert to file path format
                package_path = package_name.replace('.', '/')
                self.logger.info(f"📦 Firebase filter detected app package: {package_name} -> {package_path}/")
                return package_path
                
        except Exception as e:
            self.logger.debug(f"⚠️ Could not extract app package from manifest: {e}")
        
        return None
    
    def detect_framework_usage(self, file_path: str) -> FrameworkDetectionResult:
        """
        Enhanced Firebase detection with comprehensive service identification.
        Uses centralized constants for all patterns.
        """
        try:
            # Quick file name detection
            filename = os.path.basename(file_path).lower()
            
            # Firebase configuration files - highest confidence
            # Use centralized constants
            if any(config_file in filename for config_file in FirebaseConstants.INTEGRATION_FILES):
                return FrameworkDetectionResult(
                    framework_detected=True,
                    framework_name=self.framework_name,
                    detection_confidence=1.0,
                    detected_services=['configuration'],
                    metadata={'detection_method': 'config_file', 'file_type': 'configuration'}
                )
            
            # Path-based detection
            normalized_path = file_path.replace('\\', '/').lower()
            
            if FirebaseConstants.PACKAGE_DETECTION_STRING in normalized_path:
                # Enhanced service detection
                detected_services = self._detect_firebase_services_in_path(normalized_path)
                
                # Check if it's Firebase library internal vs app integration
                # Use centralized constants
                is_internal = any(pattern in normalized_path for pattern in FirebaseConstants.INTERNAL_PATTERNS)
                
                confidence = 0.9 if is_internal else 0.8
                detection_type = 'library_internal' if is_internal else 'app_integration'
                
                return FrameworkDetectionResult(
                    framework_detected=True,
                    framework_name=self.framework_name,
                    detection_confidence=confidence,
                    detected_services=detected_services,
                    metadata={'detection_method': 'path_analysis', 'type': detection_type}
                )
            
            # Content-based detection (for efficiency, only read small files)
            if os.path.exists(file_path) and os.path.getsize(file_path) < 10240:  # 10KB limit
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1024)  # Read first 1KB
                        
                        # Use centralized Firebase service indicators
                        content_lower = content.lower()
                        detected_services = []
                        
                        for indicator in FirebaseConstants.SERVICE_INDICATORS:
                            if indicator.lower() in content_lower:
                                detected_services.append(indicator)
                        
                        if detected_services:
                            return FrameworkDetectionResult(
                                framework_detected=True,
                                framework_name=self.framework_name,
                                detection_confidence=0.7,
                                detected_services=detected_services,
                                metadata={'detection_method': 'content_analysis'}
                            )
                            
                except Exception:
                    pass  # Ignore read errors
            
            return FrameworkDetectionResult(
                framework_detected=False,
                framework_name=self.framework_name,
                detection_confidence=0.0
            )
            
        except Exception as e:
            return FrameworkDetectionResult(
                framework_detected=False,
                framework_name=self.framework_name,
                detection_confidence=0.0,
                metadata={'error': str(e)}
            )
    
    def _detect_firebase_services_in_path(self, normalized_path: str) -> list:
        """Detect specific Firebase services from file path using centralized patterns."""
        services = []
        
        # Use centralized service patterns
        for service, patterns in FirebaseConstants.SERVICE_PATTERNS.items():
            if any(pattern in normalized_path for pattern in patterns):
                services.append(service)
        
        return services if services else ['unknown']
    
    def should_filter_file(self, file_path: str) -> FilterResult:
        """
        Comprehensive Firebase filtering logic using centralized constants.
        Implements smart filtering: filter internals, keep integration.
        """
        normalized_path = file_path.replace('\\', '/').lower()
        
        # Firebase integration files - NEVER filter these
        # Use centralized constants
        for pattern in FirebaseConstants.INTEGRATION_FILES:
            if pattern in normalized_path:
                return FilterResult(
                    should_filter=False,
                    reason=f"Firebase integration file: {pattern}",
                    framework_name=self.framework_name,
                    confidence=1.0,
                    metadata={'file_type': 'integration_config', 'pattern': pattern}
                )
        
        # App Firebase integration code - NEVER filter if in app package
        # Use centralized constants for keywords
        if self.app_package_name and FirebaseConstants.PACKAGE_DETECTION_STRING in normalized_path:
            app_pkg_path = self.app_package_name.lower()
            if app_pkg_path in normalized_path:
                # Check for framework integration keywords
                for keyword in FirebaseConstants.INTEGRATION_KEYWORDS:
                    if keyword in normalized_path:
                        return FilterResult(
                            should_filter=False,
                            reason=f"App Firebase integration code: {keyword}",
                            framework_name=self.framework_name,
                            confidence=0.9,
                            metadata={'file_type': 'app_integration', 'keyword': keyword}
                        )
                
                # General app Firebase code
                return FilterResult(
                    should_filter=False,
                    reason="App Firebase integration code",
                    framework_name=self.framework_name,
                    confidence=0.85,
                    metadata={'file_type': 'app_integration'}
                )
        
        # Firebase library internals - FILTER these
        # Use centralized constants
        for pattern in FirebaseConstants.INTERNAL_PATTERNS:
            if pattern in normalized_path:
                return FilterResult(
                    should_filter=True,
                    reason=f"Firebase library internal: {pattern}",
                    framework_name=self.framework_name,
                    confidence=0.95,
                    metadata={'file_type': 'library_internal', 'pattern': pattern}
                )
        
        # General Firebase library code (outside app package) - FILTER
        # Use centralized constants
        for pattern in FirebaseConstants.LIBRARY_PATTERNS:
            if pattern in normalized_path:
                # Check if this is within app package
                if self.app_package_name:
                    app_pkg_path = self.app_package_name.lower()
                    if app_pkg_path not in normalized_path:
                        return FilterResult(
                            should_filter=True,
                            reason=f"Firebase library code: {pattern}",
                            framework_name=self.framework_name,
                            confidence=0.8,
                            metadata={'file_type': 'library_code', 'pattern': pattern}
                        )
                else:
                    return FilterResult(
                        should_filter=True,
                        reason=f"Firebase library code: {pattern}",
                        framework_name=self.framework_name,
                        confidence=0.8,
                        metadata={'file_type': 'library_code', 'pattern': pattern}
                    )
        
        # No Firebase-specific filtering decision
        return FilterResult(
            should_filter=False,
            reason="Not Firebase-related",
            framework_name=self.framework_name,
            confidence=0.0
        )
    
    def get_excluded_patterns(self) -> Set[str]:
        """
        Get Firebase patterns that should be excluded.
        Uses centralized constants - NO DUPLICATION.
        """
        # Return centralized Firebase patterns
        return FirebaseConstants.INTERNAL_PATTERNS | FirebaseConstants.LIBRARY_PATTERNS
    
    def get_integration_patterns(self) -> Set[str]:
        """
        Get patterns that indicate Firebase integration (should NOT be filtered).
        Uses centralized constants - NO DUPLICATION.
        """
        # Return centralized Firebase integration patterns
        return FirebaseConstants.INTEGRATION_FILES | FirebaseConstants.INTEGRATION_KEYWORDS
    
    def is_app_specific_firebase_file(self, file_path: str) -> bool:
        """
        Enhanced app-specific Firebase file detection.
        Uses centralized constants for all pattern checks.
        """
        try:
            normalized_path = file_path.replace('\\', '/').lower()
            
            # Firebase integration files (always include)
            # Use centralized constants
            for indicator in FirebaseConstants.INTEGRATION_FILES:
                if indicator in normalized_path:
                    return True
            
            # App package detection
            if self.app_package_name:
                app_pkg_path = self.app_package_name.lower()
                if app_pkg_path in normalized_path and FirebaseConstants.PACKAGE_DETECTION_STRING in normalized_path:
                    return True
            
            # Configuration and resource files with Firebase content
            if any(pattern in normalized_path for pattern in [
                'assets/', 'res/', 'raw/', 'values/', 'xml/'
            ]) and FirebaseConstants.PACKAGE_DETECTION_STRING in normalized_path:
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Error checking Firebase app-specific file {file_path}: {e}")
            return False
    
    def detect_framework_integration(self, apk_ctx) -> 'FrameworkDetectionResult':
        """
        Detect Firebase framework integration in the APK context.
        
        Args:
            apk_ctx: APK analysis context containing APK path and metadata
            
        Returns:
            FrameworkDetectionResult with integration_detected attribute
        """
        try:
            from core.framework_filtering_system import FrameworkDetectionResult
            
            # Check for Firebase integration indicators
            integration_detected = False
            detected_services = []
            confidence = 0.0
            metadata = {'detection_method': 'integration_analysis'}
            
            # Check APK path for Firebase indicators
            if hasattr(apk_ctx, 'apk_path') and apk_ctx.apk_path:
                apk_path_str = str(apk_ctx.apk_path).lower()
                if 'firebase' in apk_path_str:
                    integration_detected = True
                    confidence = 0.7
                    detected_services.append('apk_path_indicator')
                    metadata['apk_path_match'] = True
            
            # Check package name for Firebase indicators
            if hasattr(apk_ctx, 'package_name') and apk_ctx.package_name:
                package_name = apk_ctx.package_name.lower()
                if 'firebase' in package_name:
                    integration_detected = True
                    confidence = max(confidence, 0.8)
                    detected_services.append('package_name_indicator')
                    metadata['package_name_match'] = True
            
            # Enhanced detection through source analysis if available
            if hasattr(apk_ctx, 'source_dir') and apk_ctx.source_dir:
                # Look for Firebase configuration files
                source_path = Path(apk_ctx.source_dir)
                for config_file in FirebaseConstants.INTEGRATION_FILES:
                    config_matches = list(source_path.rglob(f"*{config_file}*"))
                    if config_matches:
                        integration_detected = True
                        confidence = 1.0  # Highest confidence for config files
                        detected_services.append('configuration_files')
                        metadata['config_files_found'] = [str(match) for match in config_matches]
                        break
                
                # Look for Firebase package usage in source code
                firebase_imports = list(source_path.rglob("*.java"))
                firebase_imports.extend(list(source_path.rglob("*.kt")))
                
                for java_file in firebase_imports[:50]:  # Limit to prevent performance issues
                    try:
                        content = java_file.read_text(encoding='utf-8', errors='ignore')
                        if FirebaseConstants.PACKAGE_DETECTION_STRING in content:
                            integration_detected = True
                            confidence = max(confidence, 0.9)
                            detected_services.append('source_code_imports')
                            metadata['source_files_analyzed'] = True
                            break
                    except Exception:
                        continue
            
            # Create result object with integration_detected attribute
            result = FrameworkDetectionResult(
                framework_detected=integration_detected,
                framework_name=self.framework_name,
                detection_confidence=confidence,
                detected_services=detected_services,
                metadata=metadata
            )
            
            # Add the expected integration_detected attribute
            result.integration_detected = integration_detected
            
            self.logger.debug(f"🔍 Firebase integration detection: {integration_detected} (confidence: {confidence:.2f})")
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Firebase integration detection failed: {e}")
            # Return a default result on error
            from core.framework_filtering_system import FrameworkDetectionResult
            result = FrameworkDetectionResult(
                framework_detected=False,
                framework_name=self.framework_name,
                detection_confidence=0.0,
                detected_services=[],
                metadata={'error': str(e)}
            )
            result.integration_detected = False
            return result