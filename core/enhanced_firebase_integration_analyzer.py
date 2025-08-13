#!/usr/bin/env python3
"""
Enhanced Firebase Integration Security Analyzer for AODS

This module analyzes application-specific Firebase integration code for security
vulnerabilities while filtering out Firebase library internals. It addresses
the concern about missing Firebase-related vulnerabilities when framework
filtering is applied.

Addresses: Smart Firebase filtering vs comprehensive security analysis
"""

import logging
import os
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class EnhancedFirebaseIntegrationAnalyzer:
    """
    Analyzes Firebase integration security in application code while
    distinguishing between app code and Firebase library internals.
    """
    
    def __init__(self, apk_ctx):
        """Initialize the Firebase integration analyzer."""
        self.apk_ctx = apk_ctx
        self.package_name = apk_ctx.package_name
        self.app_package_path = self.package_name.replace('.', '/') if self.package_name else None
        self.decompiled_path = getattr(apk_ctx, 'decompiled_path', None)
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Firebase security patterns in APPLICATION code
        self.firebase_patterns = self._load_firebase_security_patterns()
        
    def _load_firebase_security_patterns(self) -> Dict[str, List[Dict]]:
        """Load Firebase-specific security patterns for application code."""
        return {
            'firebase_configuration_issues': [
                {
                    'name': 'Hardcoded Firebase API Keys',
                    'patterns': [
                        r'AIza[0-9A-Za-z_-]{35}',  # Firebase API key pattern
                        r'firebase_api_key\s*=\s*["\'][^"\']+["\']',
                        r'FIREBASE_API_KEY\s*=\s*["\'][^"\']+["\']',
                        r'api_key.*firebase.*["\'][^"\']{20,}["\']'
                    ],
                    'severity': 'CRITICAL',
                    'description': 'Firebase API keys hardcoded in application code',
                    'category': 'firebase_secrets'
                },
                {
                    'name': 'Hardcoded Firebase Database URLs',
                    'patterns': [
                        r'https://[a-zA-Z0-9-]+\.firebaseio\.com',
                        r'https://[a-zA-Z0-9-]+\.firebaseapp\.com',
                        r'firebase_database_url\s*=\s*["\'][^"\']+["\']',
                        r'databaseURL.*["\']https://[^"\']+firebaseio["\']'
                    ],
                    'severity': 'HIGH',
                    'description': 'Firebase database URLs exposed in application code',
                    'category': 'firebase_exposure'
                },
                {
                    'name': 'Firebase Project IDs in Code',
                    'patterns': [
                        r'project_id\s*=\s*["\'][a-zA-Z0-9-]+["\']',
                        r'projectId.*["\'][a-zA-Z0-9-]+["\']',
                        r'FIREBASE_PROJECT_ID\s*=\s*["\'][^"\']+["\']'
                    ],
                    'severity': 'MEDIUM',
                    'description': 'Firebase project IDs hardcoded in source code',
                    'category': 'firebase_configuration'
                }
            ],
            'firebase_security_rules_issues': [
                {
                    'name': 'Permissive Firebase Rules',
                    'patterns': [
                        r'\.read.*:.*true',
                        r'\.write.*:.*true',
                        r'"\.read"\s*:\s*true',
                        r'"\.write"\s*:\s*true',
                        r'allow\s+read,\s*write'
                    ],
                    'severity': 'CRITICAL',
                    'description': 'Firebase security rules allow unrestricted read/write access',
                    'category': 'firebase_rules'
                },
                {
                    'name': 'Missing Authentication in Rules',
                    'patterns': [
                        r'request\.auth\s*==\s*null',
                        r'auth\s*!=\s*null.*false',
                        r'\.read.*auth\s*==\s*undefined',
                        r'\.write.*auth\s*==\s*undefined'
                    ],
                    'severity': 'HIGH',
                    'description': 'Firebase rules missing proper authentication checks',
                    'category': 'firebase_auth'
                }
            ],
            'firebase_integration_vulnerabilities': [
                {
                    'name': 'Insecure Firebase Data Access',
                    'patterns': [
                        r'database\(\)\.ref\(["\'][^"\']*["\']\)\.set\([^)]*\)',
                        r'database\.child\([^)]*\)\.setValue\([^)]*\)',
                        r'firestore\.collection\([^)]*\)\.add\([^)]*\)',
                        r'\.push\([^)]*\)(?!\s*\.key)',  # Push without checking key
                    ],
                    'severity': 'HIGH',
                    'description': 'Potentially insecure Firebase data operations in application code',
                    'category': 'firebase_data_access'
                },
                {
                    'name': 'Firebase Auth Bypass Patterns',
                    'patterns': [
                        r'signInAnonymously\(\)',
                        r'signInWithEmailAndPassword\([^)]*,\s*["\'][^"\']*["\']',  # Hardcoded password
                        r'createUserWithEmailAndPassword\([^)]*,\s*["\'][^"\']*["\']',
                        r'auth\.currentUser\s*==\s*null.*continue'
                    ],
                    'severity': 'HIGH', 
                    'description': 'Insecure Firebase authentication patterns in app code',
                    'category': 'firebase_auth_bypass'
                },
                {
                    'name': 'Firebase Storage Security Issues',
                    'patterns': [
                        r'storage\.ref\([^)]*\)\.put\([^)]*\)',
                        r'uploadTask\.snapshot\.downloadURL',
                        r'storageRef\.child\([^)]*\)\.putFile\([^)]*\)',
                        r'getDownloadURL\(\)(?!\s*\.then)'  # Direct URL access
                    ],
                    'severity': 'MEDIUM',
                    'description': 'Potentially insecure Firebase storage operations',
                    'category': 'firebase_storage'
                }
            ],
            'firebase_configuration_files': [
                {
                    'name': 'Insecure google-services.json',
                    'patterns': [
                        r'"api_key":\s*"[^"]*"',
                        r'"project_id":\s*"[^"]*"',
                        r'"client_id":\s*"[^"]*"',
                        r'"current_key":\s*"[^"]*"'
                    ],
                    'severity': 'HIGH',
                    'description': 'Firebase configuration file contains sensitive information',
                    'category': 'firebase_config_file'
                }
            ]
        }
    
    def analyze_firebase_integration_security(self) -> Dict[str, Any]:
        """
        Analyze Firebase integration security in application-specific code.
        
        Returns:
            Comprehensive Firebase security analysis results
        """
        self.logger.info("🔥 Starting Firebase integration security analysis...")
        start_time = __import__('time').time()
        
        results = {
            'analysis_type': 'firebase_integration_security',
            'package_name': self.package_name,
            'app_package_path': self.app_package_path,
            'timestamp': start_time,
            'firebase_vulnerabilities': [],
            'firebase_configuration_files': [],
            'summary': {
                'total_findings': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'analysis_scope': {
                'firebase_library_files': 'filtered_out',
                'app_firebase_integration': 'analyzed',
                'firebase_config_files': 'analyzed',
                'firebase_rules_files': 'analyzed'
            }
        }
        
        try:
            # 1. Analyze application code for Firebase integration issues
            if self.decompiled_path and os.path.exists(self.decompiled_path):
                app_findings = self._analyze_app_firebase_code()
                results['firebase_vulnerabilities'].extend(app_findings)
            
            # 2. Analyze Firebase configuration files
            config_findings = self._analyze_firebase_config_files()
            results['firebase_vulnerabilities'].extend(config_findings)
            results['firebase_configuration_files'] = self._get_firebase_config_files()
            
            # 3. Analyze Firebase rules files (if present)
            rules_findings = self._analyze_firebase_rules()
            results['firebase_vulnerabilities'].extend(rules_findings)
            
            # 4. Update summary statistics
            results['summary'] = self._calculate_firebase_summary_stats(results['firebase_vulnerabilities'])
            
            # 5. Add analysis metadata
            results['analysis_duration'] = __import__('time').time() - start_time
            results['files_analyzed'] = self._count_firebase_analyzed_files()
            
            self.logger.info(f"✅ Firebase integration analysis completed: {results['summary']['total_findings']} findings")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Firebase integration analysis failed: {e}")
            return self._create_firebase_error_result(str(e))
    
    def _analyze_app_firebase_code(self) -> List[Dict[str, Any]]:
        """Analyze application code for Firebase integration vulnerabilities."""
        findings = []
        
        try:
            # Only analyze files in the app package (not Firebase library files)
            app_files = self._get_app_specific_files()
            
            self.logger.info(f"🔍 Analyzing {len(app_files)} app-specific files for Firebase integration...")
            
            for file_path in app_files:
                if self._is_likely_firebase_integration_file(file_path):
                    file_findings = self._analyze_firebase_integration_file(file_path)
                    findings.extend(file_findings)
            
            return findings
            
        except Exception as e:
            self.logger.error(f"App Firebase code analysis failed: {e}")
            return []
    
    def _get_app_specific_files(self) -> List[str]:
        """Get files that belong to the application (not framework libraries)."""
        app_files = []
        
        if not self.decompiled_path or not os.path.exists(self.decompiled_path):
            return app_files
        
        try:
            for root, dirs, files in os.walk(self.decompiled_path):
                for file in files:
                    if file.endswith(('.java', '.kt', '.js', '.json', '.xml')):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, self.decompiled_path)
                        
                        # Include if it's in the app package or likely app-related
                        if self._is_app_specific_file(relative_path):
                            app_files.append(file_path)
            
            return app_files[:50]  # Limit for performance
            
        except Exception as e:
            self.logger.debug(f"Failed to get app-specific files: {e}")
            return []
    
    def _is_app_specific_file(self, file_path: str) -> bool:
        """Check if a file belongs to the application (not framework)."""
        normalized_path = file_path.replace('\\', '/').lower()
        
        # Include if in app package
        if self.app_package_path and self.app_package_path.lower() in normalized_path:
            return True
        
        # Include configuration and resource files
        if any(pattern in normalized_path for pattern in [
            'assets/', 'res/', 'google-services.json', 'firebase', 'config'
        ]):
            return True
        
        # Exclude known framework paths
        framework_patterns = [
            'com/google/firebase/internal',
            'com/google/firebase/impl',
            'com/google/android/gms/internal',
            'com/android/', 'androidx/', 'kotlin/jvm/internal'
        ]
        
        for pattern in framework_patterns:
            if pattern in normalized_path:
                return False
        
        return True
    
    def _is_likely_firebase_integration_file(self, file_path: str) -> bool:
        """Check if a file likely contains Firebase integration code."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000)  # Read first 1KB
            
            # Look for Firebase imports or usage
            firebase_indicators = [
                'firebase', 'FirebaseApp', 'FirebaseDatabase', 'FirebaseAuth',
                'FirebaseStorage', 'FirebaseFirestore', 'google-services'
            ]
            
            content_lower = content.lower()
            return any(indicator.lower() in content_lower for indicator in firebase_indicators)
            
        except Exception:
            return False
    
    def _analyze_firebase_integration_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze a single file for Firebase integration vulnerabilities."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check each Firebase vulnerability category
            for category, patterns in self.firebase_patterns.items():
                for pattern_info in patterns:
                    for pattern in pattern_info['patterns']:
                        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                        
                        for match in matches:
                            # Extract line number and context
                            line_number = content[:match.start()].count('\n') + 1
                            lines = content.split('\n')
                            start_line = max(0, line_number - 2)
                            end_line = min(len(lines), line_number + 1)
                            context = '\n'.join(lines[start_line:end_line])
                            
                            finding = {
                                'vulnerability_id': f"firebase_{hash(f'{file_path}_{pattern}_{line_number}')}",
                                'title': f"Firebase Integration: {pattern_info['name']}",
                                'description': pattern_info['description'],
                                'severity': pattern_info['severity'],
                                'confidence': 0.8,
                                'file_path': os.path.relpath(file_path, self.decompiled_path),
                                'line_number': line_number,
                                'vulnerable_code': match.group(0),
                                'surrounding_context': context,
                                'category': pattern_info['category'],
                                'analysis_method': 'firebase_integration_analysis',
                                'pattern_matched': pattern,
                                'masvs_control': 'MASVS-STORAGE-1',
                                'remediation': self._get_firebase_remediation(pattern_info['name']),
                                'firebase_specific': True
                            }
                            
                            findings.append(finding)
            
            return findings
            
        except Exception as e:
            self.logger.debug(f"Failed to analyze Firebase file {file_path}: {e}")
            return []
    
    def _analyze_firebase_config_files(self) -> List[Dict[str, Any]]:
        """Analyze Firebase configuration files for security issues."""
        findings = []
        
        try:
            # Look for google-services.json and other config files
            config_files = self._find_firebase_config_files()
            
            for config_file in config_files:
                config_findings = self._analyze_firebase_config_file(config_file)
                findings.extend(config_findings)
            
            return findings
            
        except Exception as e:
            self.logger.debug(f"Firebase config analysis failed: {e}")
            return []
    
    def _find_firebase_config_files(self) -> List[str]:
        """Find Firebase configuration files in the APK."""
        config_files = []
        
        if not self.decompiled_path or not os.path.exists(self.decompiled_path):
            return config_files
        
        try:
            for root, dirs, files in os.walk(self.decompiled_path):
                for file in files:
                    if file in ['google-services.json', 'firebase-config.json', 'firebase.json']:
                        config_files.append(os.path.join(root, file))
            
            return config_files
            
        except Exception as e:
            self.logger.debug(f"Failed to find Firebase config files: {e}")
            return []
    
    def _analyze_firebase_config_file(self, config_file_path: str) -> List[Dict[str, Any]]:
        """Analyze a Firebase configuration file."""
        findings = []
        
        try:
            with open(config_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for sensitive data in config
            if 'google-services.json' in config_file_path:
                try:
                    config_data = json.loads(content)
                    
                    # Check for exposed sensitive fields
                    sensitive_fields = ['api_key', 'client_id', 'project_id', 'storage_bucket']
                    for field in sensitive_fields:
                        if self._find_sensitive_config_data(config_data, field):
                            finding = {
                                'vulnerability_id': f"firebase_config_{hash(f'{config_file_path}_{field}')}",
                                'title': f"Firebase Config: Exposed {field.replace('_', ' ').title()}",
                                'description': f"Firebase configuration file exposes {field} which could be used maliciously",
                                'severity': 'HIGH',
                                'confidence': 0.9,
                                'file_path': os.path.relpath(config_file_path, self.decompiled_path),
                                'category': 'firebase_config_exposure',
                                'analysis_method': 'firebase_config_analysis',
                                'masvs_control': 'MASVS-STORAGE-1',
                                'remediation': f'Protect {field} and use environment-specific configuration',
                                'firebase_specific': True
                            }
                            findings.append(finding)
                
                except json.JSONDecodeError:
                    pass
            
            return findings
            
        except Exception as e:
            self.logger.debug(f"Failed to analyze Firebase config file {config_file_path}: {e}")
            return []
    
    def _find_sensitive_config_data(self, config_data: dict, field: str) -> bool:
        """Check if sensitive configuration data is present."""
        def search_dict(d, key):
            if isinstance(d, dict):
                if key in d and d[key]:
                    return True
                for v in d.values():
                    if search_dict(v, key):
                        return True
            elif isinstance(d, list):
                for item in d:
                    if search_dict(item, key):
                        return True
            return False
        
        return search_dict(config_data, field)
    
    def _analyze_firebase_rules(self) -> List[Dict[str, Any]]:
        """Analyze Firebase security rules if present."""
        findings = []
        
        try:
            # Look for Firebase rules files
            rules_files = self._find_firebase_rules_files()
            
            for rules_file in rules_files:
                rules_findings = self._analyze_firebase_rules_file(rules_file)
                findings.extend(rules_findings)
            
            return findings
            
        except Exception as e:
            self.logger.debug(f"Firebase rules analysis failed: {e}")
            return []
    
    def _find_firebase_rules_files(self) -> List[str]:
        """Find Firebase rules files."""
        rules_files = []
        
        if not self.decompiled_path or not os.path.exists(self.decompiled_path):
            return rules_files
        
        try:
            for root, dirs, files in os.walk(self.decompiled_path):
                for file in files:
                    if any(pattern in file.lower() for pattern in ['firebase.rules', 'firestore.rules', 'storage.rules']):
                        rules_files.append(os.path.join(root, file))
            
            return rules_files
            
        except Exception as e:
            self.logger.debug(f"Failed to find Firebase rules files: {e}")
            return []
    
    def _analyze_firebase_rules_file(self, rules_file_path: str) -> List[Dict[str, Any]]:
        """Analyze Firebase security rules file."""
        findings = []
        
        try:
            with open(rules_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for insecure rules patterns
            rules_patterns = self.firebase_patterns.get('firebase_security_rules_issues', [])
            
            for pattern_info in rules_patterns:
                for pattern in pattern_info['patterns']:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        line_number = content[:match.start()].count('\n') + 1
                        
                        finding = {
                            'vulnerability_id': f"firebase_rules_{hash(f'{rules_file_path}_{pattern}_{line_number}')}",
                            'title': f"Firebase Rules: {pattern_info['name']}",
                            'description': pattern_info['description'],
                            'severity': pattern_info['severity'],
                            'confidence': 0.9,
                            'file_path': os.path.relpath(rules_file_path, self.decompiled_path),
                            'line_number': line_number,
                            'vulnerable_code': match.group(0),
                            'category': pattern_info['category'],
                            'analysis_method': 'firebase_rules_analysis',
                            'masvs_control': 'MASVS-AUTH-1',
                            'remediation': self._get_firebase_remediation(pattern_info['name']),
                            'firebase_specific': True
                        }
                        
                        findings.append(finding)
            
            return findings
            
        except Exception as e:
            self.logger.debug(f"Failed to analyze Firebase rules file {rules_file_path}: {e}")
            return []
    
    def _get_firebase_config_files(self) -> List[Dict[str, str]]:
        """Get information about Firebase configuration files found."""
        config_files = []
        
        try:
            firebase_configs = self._find_firebase_config_files()
            
            for config_file in firebase_configs:
                config_info = {
                    'file_path': os.path.relpath(config_file, self.decompiled_path),
                    'file_name': os.path.basename(config_file),
                    'file_type': 'firebase_configuration',
                    'security_concern': 'Contains Firebase API keys and configuration'
                }
                config_files.append(config_info)
            
            return config_files
            
        except Exception as e:
            self.logger.debug(f"Failed to get Firebase config file info: {e}")
            return []
    
    def _calculate_firebase_summary_stats(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate summary statistics for Firebase vulnerabilities."""
        stats = {'total_findings': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerabilities:
            stats['total_findings'] += 1
            severity = vuln.get('severity', 'LOW').upper()
            stats[severity.lower()] += 1
        
        return stats
    
    def _count_firebase_analyzed_files(self) -> int:
        """Count the number of Firebase-related files analyzed."""
        try:
            app_files = self._get_app_specific_files()
            firebase_files = [f for f in app_files if self._is_likely_firebase_integration_file(f)]
            config_files = self._find_firebase_config_files()
            rules_files = self._find_firebase_rules_files()
            
            return len(firebase_files) + len(config_files) + len(rules_files)
            
        except Exception:
            return 0
    
    def _get_firebase_remediation(self, vulnerability_name: str) -> str:
        """Get remediation advice for Firebase vulnerabilities."""
        remediations = {
            'Hardcoded Firebase API Keys': 'Store Firebase API keys in secure configuration, use build-time injection',
            'Hardcoded Firebase Database URLs': 'Use environment-specific configuration for Firebase URLs',
            'Firebase Project IDs in Code': 'Move project IDs to build configuration or environment variables',
            'Permissive Firebase Rules': 'Implement strict Firebase security rules with proper authentication',
            'Missing Authentication in Rules': 'Add authentication checks to all Firebase security rules',
            'Insecure Firebase Data Access': 'Implement proper authentication and authorization for Firebase operations',
            'Firebase Auth Bypass Patterns': 'Use secure authentication patterns and avoid hardcoded credentials',
            'Firebase Storage Security Issues': 'Implement proper access controls for Firebase storage operations'
        }
        return remediations.get(vulnerability_name, 'Review Firebase integration security best practices')
    
    def _create_firebase_error_result(self, error_message: str) -> Dict[str, Any]:
        """Create error result when Firebase analysis fails."""
        return {
            'analysis_type': 'firebase_integration_security',
            'package_name': self.package_name,
            'timestamp': __import__('time').time(),
            'success': False,
            'error': error_message,
            'firebase_vulnerabilities': [],
            'summary': {'total_findings': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }


def analyze_firebase_integration(apk_ctx) -> Dict[str, Any]:
    """
    Main function to analyze Firebase integration security.
    
    This function provides the solution to the concern about filtering out
    Firebase files while missing Firebase integration vulnerabilities.
    
    Args:
        apk_ctx: APK context containing analysis targets
        
    Returns:
        Comprehensive Firebase integration security analysis
    """
    analyzer = EnhancedFirebaseIntegrationAnalyzer(apk_ctx)
    return analyzer.analyze_firebase_integration_security()