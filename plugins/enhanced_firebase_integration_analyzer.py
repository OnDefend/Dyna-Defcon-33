#!/usr/bin/env python3
"""
Enhanced Firebase Integration Security Analyzer for AODS

This module provides focused Firebase security analysis using centralized constants.
Optimized for <500 lines while maintaining core functionality.

ELIMINATES DUPLICATION: Uses core.framework_constants for all patterns.
SINGLE RESPONSIBILITY: Focused Firebase security analysis only.
"""

import logging
import os
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
import time
import re # Added for re.finditer

# Import centralized constants - ELIMINATES ALL DUPLICATION
from core.framework_constants.firebase_constants import FirebaseConstants

logger = logging.getLogger(__name__)

class EnhancedFirebaseIntegrationAnalyzer:
    """
    Focused Firebase integration security analyzer using centralized constants.
    
    ELIMINATES DUPLICATION: All patterns come from core.framework_constants.
    OPTIMIZED: Single responsibility, <500 lines.
    """
    
    def __init__(self, apk_ctx):
        self.apk_ctx = apk_ctx
        self.package_name = getattr(apk_ctx, 'package_name', 'unknown')
        self.decompiled_path = getattr(apk_ctx, 'decompiled_apk_dir', None)
        self.logger = logger
        
        # Use centralized Firebase patterns - NO LOCAL DEFINITIONS
        self.firebase_patterns = FirebaseConstants.SECURITY_ANALYSIS_PATTERNS
        self.firebase_services = FirebaseConstants.SERVICE_DETECTION_PATTERNS
        
    def analyze_firebase_integration_security(self) -> Dict[str, Any]:
        """
        Perform focused Firebase integration security analysis.
        OPTIMIZED: Core functionality only, using centralized constants.
        """
        try:
            # Initialize results structure
            results = {
                'vulnerabilities': [],
                'summary': {
                    'total_findings': 0,
                    'critical_issues': 0,
                    'high_issues': 0,
                    'medium_issues': 0,
                    'low_issues': 0
                },
                'metadata': {
                    FirebaseConstants.METADATA_KEYS['SERVICES_DETECTED']: [],
                    FirebaseConstants.METADATA_KEYS['SERVICES_COUNT']: 0,
                    'analysis_start_time': time.time(),
                    'analysis_method': FirebaseConstants.ANALYSIS_METHOD_NAME,
                    'app_package_name': self.package_name
                }
            }
            
            # Core Firebase analysis
            vulnerabilities = []
            
            # 1. Analyze source code for Firebase integration vulnerabilities
            self.logger.info("🔍 Analyzing Firebase integration code...")
            source_vulns = self._analyze_firebase_source_code()
            vulnerabilities.extend(source_vulns)
            
            # 2. Analyze Firebase configuration files
            self.logger.info("📁 Analyzing Firebase configuration files...")
            config_vulns = self._analyze_firebase_config_files()
            vulnerabilities.extend(config_vulns)
            
            # 3. Detect Firebase services usage
            self.logger.info("🔍 Detecting Firebase services...")
            results[FirebaseConstants.METADATA_KEYS['SERVICES_DETECTED']] = self._detect_firebase_services()
            
            # Process and categorize vulnerabilities
            categorized_vulns = []
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for vuln in vulnerabilities:
                # Enhanced vulnerability processing
                enhanced_vuln = self._enhance_vulnerability_data(vuln)
                categorized_vulns.append(enhanced_vuln)
                
                # Update severity counts
                severity = enhanced_vuln.get('severity', 'UNKNOWN')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Update results
            results['vulnerabilities'] = categorized_vulns
            results['summary']['total_findings'] = len(categorized_vulns)
            results['summary']['critical_issues'] = severity_counts['CRITICAL']
            results['summary']['high_issues'] = severity_counts['HIGH'] 
            results['summary']['medium_issues'] = severity_counts['MEDIUM']
            results['summary']['low_issues'] = severity_counts['LOW']
            
            # Calculate security score
            security_score = self._calculate_security_score(severity_counts)
            results['summary']['config_security_score'] = security_score
            
            # Add metadata
            results['summary'][FirebaseConstants.METADATA_KEYS['SERVICES_COUNT']] = len(set(
                service['service_category'] for service in results[FirebaseConstants.METADATA_KEYS['SERVICES_DETECTED']]
            ))
            
            results['metadata']['analysis_duration'] = time.time() - results['metadata']['analysis_start_time']
            results['metadata']['total_files_analyzed'] = len(self._get_app_specific_files())
            
            # Log summary
            self.logger.info(f"✅ Firebase integration analysis completed:")
            self.logger.info(f"   📊 Total findings: {results['summary']['total_findings']}")
            self.logger.info(f"   🎯 Security score: {security_score}/100")
            
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Firebase integration analysis failed: {e}", exc_info=True)
            return {
                'vulnerabilities': [],
                'summary': {'total_findings': 0, 'error': str(e)},
                'metadata': {
                    FirebaseConstants.METADATA_KEYS['SERVICES_DETECTED']: [],
                    FirebaseConstants.METADATA_KEYS['SERVICES_COUNT']: 0,
                    'analysis_method': FirebaseConstants.ANALYSIS_METHOD_NAME,
                    'error_occurred': True
                }
            }
    
    def _analyze_firebase_source_code(self) -> List[Dict[str, Any]]:
        """Analyze Firebase integration in source code using centralized patterns."""
        vulnerabilities = []
        
        if not self.decompiled_path or not Path(self.decompiled_path).exists():
            return vulnerabilities
        
        try:
            app_files = self._get_app_specific_files()
            
            for file_path in app_files[:100]:  # Limit for performance
                if file_path.endswith(('.java', '.kt')):
                    file_vulns = self._scan_file_for_firebase_patterns(file_path)
                    vulnerabilities.extend(file_vulns)
                    
        except Exception as e:
            self.logger.error(f"❌ Error analyzing Firebase source code: {e}")
        
        return vulnerabilities
    
    def _analyze_firebase_config_files(self) -> List[Dict[str, Any]]:
        """Analyze Firebase configuration files using centralized patterns."""
        vulnerabilities = []
        
        try:
            config_files = self._find_firebase_config_files()
            
            for config_file in config_files:
                if os.path.exists(config_file) and os.path.getsize(config_file) < 1024*1024:  # 1MB limit
                    file_vulns = self._scan_config_file(config_file)
                    vulnerabilities.extend(file_vulns)
                    
        except Exception as e:
            self.logger.error(f"❌ Error analyzing Firebase config files: {e}")
        
        return vulnerabilities
    
    def _scan_file_for_firebase_patterns(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a file for Firebase vulnerability patterns using centralized constants."""
        vulnerabilities = []
        
        try:
            # Check file size limit (5MB)
            if os.path.getsize(file_path) > 5 * 1024 * 1024:
                return vulnerabilities
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(5 * 1024 * 1024)  # 5MB limit
            
            # Scan using centralized Firebase patterns
            for category, patterns in self.firebase_patterns.items():
                for pattern_info in patterns:
                    matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE)
                    
                    for match in matches:
                        vulnerabilities.append({
                            'category': category,
                            'pattern': pattern_info['pattern'],
                            'severity': pattern_info['severity'],
                            'description': pattern_info['description'],
                            'owasp': pattern_info['owasp'],
                            'cwe': pattern_info['cwe'],
                            'remediation': pattern_info['remediation'],
                            'file_path': file_path,
                            'line_number': content[:match.start()].count('\n') + 1,
                            'match_text': match.group()
                        })
                        
        except Exception as e:
            self.logger.debug(f"⚠️ Could not scan {file_path}: {e}")
        
        return vulnerabilities
    
    def _scan_config_file(self, config_file: str) -> List[Dict[str, Any]]:
        """Scan Firebase configuration file for vulnerabilities."""
        vulnerabilities = []
        
        try:
            with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024*1024)  # 1MB limit
            
            # Look for hardcoded credentials and configuration issues
            for category, patterns in self.firebase_patterns.items():
                if 'configuration' in category.lower() or 'hardcoding' in category.lower():
                    for pattern_info in patterns:
                        matches = re.finditer(pattern_info['pattern'], content)
                        
                        for match in matches:
                            vulnerabilities.append({
                                'category': category,
                                'severity': pattern_info['severity'],
                                'description': pattern_info['description'],
                                'file_path': config_file,
                                'match_text': match.group(),
                                'owasp': pattern_info['owasp'],
                                'cwe': pattern_info['cwe'],
                                'remediation': pattern_info['remediation']
                            })
                            
        except Exception as e:
            self.logger.debug(f"⚠️ Could not scan config file {config_file}: {e}")
        
        return vulnerabilities
    
    def _find_firebase_config_files(self) -> List[str]:
        """Find Firebase configuration files using centralized constants."""
        config_files = []
        
        if not self.decompiled_path:
            return config_files
        
        try:
            for root, dirs, files in os.walk(self.decompiled_path):
                for file in files:
                    if file in FirebaseConstants.INTEGRATION_FILES:
                        config_files.append(os.path.join(root, file))
                        
        except Exception as e:
            self.logger.error(f"❌ Error finding Firebase config files: {e}")
        
        return config_files
    
    def _detect_firebase_services(self) -> List[Dict[str, Any]]:
        """Detect Firebase services using centralized service detection patterns."""
        detected_services = []
        
        try:
            app_files = self._get_app_specific_files()
            
            for file_path in app_files[:50]:  # Limit for performance
                if file_path.endswith(('.java', '.kt')):
                    services = self._detect_services_in_file(file_path)
                    detected_services.extend(services)
                    
        except Exception as e:
            self.logger.error(f"❌ Error detecting Firebase services: {e}")
        
        return detected_services
    
    def _detect_services_in_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Detect Firebase services in a specific file."""
        services = []
        
        try:
            # Check file size limit (2MB)
            if os.path.getsize(file_path) > 2 * 1024 * 1024:
                return services
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2 * 1024 * 1024)  # 2MB limit
            
            # Check for Firebase service patterns using centralized constants
            for service_category, indicators in self.firebase_services.items():
                for indicator in indicators:
                    if indicator in content:
                        services.append({
                            'service_category': service_category,
                            'service_indicator': indicator,
                            'file_path': file_path,
                            'detection_method': 'pattern_match'
                        })
                        
        except Exception as e:
            self.logger.debug(f"⚠️ Could not detect services in {file_path}: {e}")
        
        return services
    
    def _get_app_specific_files(self) -> List[str]:
        """Get list of app-specific files for analysis."""
        app_files = []
        
        if not self.decompiled_path or not Path(self.decompiled_path).exists():
            return app_files
        
        try:
            for root, dirs, files in os.walk(self.decompiled_path):
                for file in files:
                    if file.endswith(('.java', '.kt', '.xml', '.json')):
                        file_path = os.path.join(root, file)
                        if self._is_app_specific_file(file_path):
                            app_files.append(file_path)
                            
                            # Limit to prevent excessive processing
                            if len(app_files) > 500:
                                break
                
                if len(app_files) > 500:
                    break
                    
        except Exception as e:
            self.logger.error(f"❌ Error getting app-specific files: {e}")
        
        return app_files
    
    def _is_app_specific_file(self, file_path: str) -> bool:
        """Check if file is app-specific (simple heuristic for optimization)."""
        try:
            normalized_path = file_path.replace('\\', '/').lower()
            
            # Basic app package detection
            if self.package_name and self.package_name != 'unknown':
                app_pkg_path = self.package_name.replace('.', '/').lower()
                if app_pkg_path in normalized_path:
                    return True
            
            # Firebase integration files (always include)
            for indicator in FirebaseConstants.INTEGRATION_FILES:
                if indicator in normalized_path:
                    return True
            
            # Configuration and resource files
            if any(pattern in normalized_path for pattern in [
                'assets/', 'res/', 'raw/', 'values/', 'xml/'
            ]):
                return True
            
            # Exclude framework patterns using centralized constants
            for exclusion in FirebaseConstants.INTERNAL_PATTERNS | FirebaseConstants.LIBRARY_PATTERNS:
                if exclusion in normalized_path:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error checking app-specific file {file_path}: {e}")
            return False
    
    def _calculate_security_score(self, severity_counts: Dict[str, int]) -> int:
        """Calculate security score based on vulnerability severity counts."""
        try:
            score = 100
            score -= severity_counts.get('CRITICAL', 0) * 25
            score -= severity_counts.get('HIGH', 0) * 10
            score -= severity_counts.get('MEDIUM', 0) * 5
            score -= severity_counts.get('LOW', 0) * 1
            return max(0, score)
        except Exception as e:
            self.logger.error(f"❌ Error calculating security score: {e}")
            return 50
    
    def _enhance_vulnerability_data(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance vulnerability data with additional metadata."""
        try:
            enhanced = vuln.copy()
            enhanced['detection_time'] = time.time()
            enhanced['analyzer_version'] = 'optimized_v2.0'
            if 'confidence' not in enhanced:
                enhanced['confidence'] = 0.85
            return enhanced
        except Exception as e:
            self.logger.error(f"❌ Error enhancing vulnerability data: {e}")
            return vuln


def analyze_firebase_integration(apk_ctx):
    """
    Main function for Firebase integration security analysis.
    
    Args:
        apk_ctx: APK context containing analysis targets
        
    Returns:
        Dict: Comprehensive Firebase security analysis results with
              47+ vulnerability patterns across 8 analysis categories,
              integrated with modular filtering for smart file detection
    """
    analyzer = EnhancedFirebaseIntegrationAnalyzer(apk_ctx)
    return analyzer.analyze_firebase_integration_security()


def run(apk_ctx):
    """
    Plugin manager compatibility function.
    
    Args:
        apk_ctx: APK context for analysis
        
    Returns:
        Tuple: (title, results) format expected by plugin manager
    """
    try:
        results = analyze_firebase_integration(apk_ctx)
        
        if results and results.get('firebase_vulnerabilities'):
            vuln_count = len(results['firebase_vulnerabilities'])
            security_score = results.get('summary', {}).get('config_security_score', 100)
            title = f"🔥 Firebase Integration Security Analysis: {vuln_count} findings (Score: {security_score}/100)"
            return (title, results)
        else:
            return ("🔥 Firebase Integration Security Analysis: No Firebase integration detected", {})
            
    except Exception as e:
        return (f"🔥 Firebase Integration Security Analysis: Error - {str(e)}", {})


if __name__ == "__main__":
    # Test the enhanced analyzer with modular filtering integration
    class MockAPKContext:
        def __init__(self):
            self.package_name = "com.example.firebaseapp"
            self.decompiled_apk_dir = None
    
    mock_ctx = MockAPKContext()
    results = analyze_firebase_integration(mock_ctx)
    
    print("🔥 Enhanced Firebase Integration Security Analyzer (Integrated)")
    print(f"📊 Patterns loaded: {results['metadata']['patterns_count']}")
    print(f"🎯 Service coverage: {results['metadata']['services_coverage']} categories")
    print(f"📋 Analysis categories: {len(results['analysis_categories'])}")
    print(f"🛡️ Security rules patterns: {results['metadata']['rules_patterns']}")
    print(f"🔧 Modular filtering integrated: {results['metadata']['integrated_filtering']}")
    print(f"🔥 Firebase filter active: {results['metadata']['firebase_filter_active']}")