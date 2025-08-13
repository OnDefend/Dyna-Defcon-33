"""
Enhanced Static Analysis - Static Analyzer Component

This module provides comprehensive static analysis capabilities including
pattern matching, vulnerability detection, and security assessment.
"""

import logging
import re
from typing import Dict, List, Optional, Any, Pattern
from pathlib import Path
import os
import fnmatch
import yaml

from .data_structures import (
    SecurityFinding, RiskLevel, SeverityLevel, AnalysisType,
    FindingCategory, StaticAnalysisResult, AnalysisConfiguration
)
from .confidence_calculator import StaticAnalysisConfidenceCalculator

# ML-Enhanced Confidence Calculator Integration
try:
    from core.ml_enhanced_confidence_calculator import get_ml_confidence_calculator
    ML_ENHANCED_CONFIDENCE_AVAILABLE = True
except ImportError:
    ML_ENHANCED_CONFIDENCE_AVAILABLE = False

class StaticAnalyzer:
    """Advanced static analyzer for security vulnerability detection."""
    
    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """Initialize the static analyzer with configuration."""
        self.config = config or AnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        self.compiled_patterns = {}
        
        # Initialize confidence calculators - ML-enhanced when available
        self.confidence_calculator = StaticAnalysisConfidenceCalculator(config)
        self.ml_confidence_calculator = None
        
        if ML_ENHANCED_CONFIDENCE_AVAILABLE:
            try:
                self.ml_confidence_calculator = get_ml_confidence_calculator()
                self.logger.info("ML-enhanced confidence calculation enabled")
            except Exception as e:
                self.logger.warning(f"Failed to initialize ML confidence calculator: {e}")
        else:
            self.logger.info("ML-enhanced confidence calculation not available - using traditional methods")
        
        self._load_security_patterns()
    
    def _load_security_patterns(self) -> None:
        """Load comprehensive security patterns from YAML configuration files."""
        self.security_patterns = {}
        
        # Load main vulnerability patterns
        config_paths = [
            'config/vulnerability_patterns.yaml',
            'config/kotlin_vulnerability_patterns.yaml', 
            'config/framework_vulnerability_patterns.yaml'
        ]
        
        for config_path in config_paths:
            try:
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        config_data = yaml.safe_load(f)
                        if config_data:
                            self._process_pattern_config(config_data)
                            self.logger.debug(f"Loaded vulnerability patterns from {config_path}")
                else:
                    self.logger.warning(f"Pattern file not found: {config_path}")
            except Exception as e:
                self.logger.error(f"Error loading patterns from {config_path}: {e}")
        
        # Fallback to basic patterns if no configs loaded
        if not self.security_patterns:
            self.logger.warning("No pattern configs loaded, using fallback patterns")
            self._load_fallback_patterns()
        
        # Compile patterns for performance
        for category, pattern_info in self.security_patterns.items():
            self.compiled_patterns[category] = []
            for pattern in pattern_info['patterns']:
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    self.compiled_patterns[category].append(compiled_pattern)
                except re.error as e:
                    self.logger.warning(f"Failed to compile pattern {pattern}: {e}")
    
    def _process_pattern_config(self, config_data: Dict[str, Any]) -> None:
        """Process YAML configuration data into security patterns."""
        # Skip metadata fields
        skip_fields = {'version', 'last_updated', 'created', 'file_filters', 'deduplication', 'context_extraction', 'min_confidence'}
        
        for category, category_data in config_data.items():
            if category in skip_fields or not isinstance(category_data, dict):
                continue
                
            # Process each subcategory (e.g., android_debuggable, sqlite_insecure, etc.)
            for subcategory, subcategory_data in category_data.items():
                if not isinstance(subcategory_data, dict) or 'patterns' not in subcategory_data:
                    continue
                    
                patterns_list = subcategory_data.get('patterns', [])
                if not patterns_list:
                    continue
                
                # Convert patterns to the format expected by StaticAnalyzer
                pattern_key = f"{category}_{subcategory}"
                pattern_regexes = []
                
                for pattern_info in patterns_list:
                    if isinstance(pattern_info, dict) and 'pattern' in pattern_info:
                        pattern_regexes.append(pattern_info['pattern'])
                    elif isinstance(pattern_info, str):
                        pattern_regexes.append(pattern_info)
                
                if pattern_regexes:
                    # Map severity from YAML to our enum
                    severity_map = {
                        'CRITICAL': SeverityLevel.CRITICAL,
                        'HIGH': SeverityLevel.HIGH, 
                        'MEDIUM': SeverityLevel.MEDIUM,
                        'LOW': SeverityLevel.LOW,
                        'INFO': SeverityLevel.LOW
                    }
                    
                    # Get pattern metadata
                    first_pattern = patterns_list[0] if patterns_list else {}
                    severity_str = first_pattern.get('severity', 'MEDIUM') if isinstance(first_pattern, dict) else 'MEDIUM'
                    severity = severity_map.get(severity_str, SeverityLevel.MEDIUM)
                    
                    title = first_pattern.get('title', f'{category} {subcategory}') if isinstance(first_pattern, dict) else f'{category} {subcategory}'
                    description = first_pattern.get('description', f'{category} vulnerability detected') if isinstance(first_pattern, dict) else f'{category} vulnerability detected'
                    
                    self.security_patterns[pattern_key] = {
                        'patterns': pattern_regexes,
                        'severity': severity,
                        'category': FindingCategory.SECURITY_VULNERABILITY,
                        'description': description,
                        'title': title
                    }
        
        self.logger.info(f"Loaded {len(self.security_patterns)} comprehensive security pattern categories")
        
        # Log enhanced pattern availability
        enhanced_patterns = ['input_validation_sql_injection', 'code_quality_hardcoded_secrets', 'android_allowbackup']
        enhanced_count = sum(1 for pattern in enhanced_patterns if pattern in self.security_patterns)
        if enhanced_count > 0:
            self.logger.debug(f"Enhanced patterns available: {enhanced_count}/{len(enhanced_patterns)}")
    
    def _load_fallback_patterns(self) -> None:
        """Load basic fallback patterns if YAML configs are not available."""
        self.security_patterns = {
            'crypto_md5': {
                'patterns': [r'(?i)MD5\s*\(', r'(?i)MessageDigest\.getInstance\s*\(\s*["\']MD5["\']'],
                'severity': SeverityLevel.MEDIUM,
                'category': FindingCategory.SECURITY_VULNERABILITY,
                'description': 'Weak hash algorithm MD5 detected',
                'title': 'Weak Hash Algorithm: MD5'
            },
            'logging_sensitive': {
                'patterns': [r'(?i)Log\.[dviwe]\s*\(\s*.*(?:password|secret|token).*\)'],
                'severity': SeverityLevel.MEDIUM,
                'category': FindingCategory.SECURITY_VULNERABILITY,
                'description': 'Sensitive data in logs detected',
                'title': 'Sensitive Data in Logs'
            }
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityFinding]:
        """Analyze a single file for security vulnerabilities."""
        findings = []
        
        if not content or len(content) > self.config.max_file_size:
            return findings
        
        # Check if file should be excluded
        if self._should_exclude_file(file_path):
            return findings
        
        # Apply security patterns
        file_findings_count = 0
        for category, patterns in self.compiled_patterns.items():
            pattern_info = self.security_patterns[category]
            
            for pattern in patterns:
                matches = pattern.finditer(content)
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Extract code snippet
                    lines = content.split('\n')
                    snippet_start = max(0, line_number - 3)
                    snippet_end = min(len(lines), line_number + 2)
                    code_snippet = '\n'.join(lines[snippet_start:snippet_end])
                    
                    # Calculate confidence based on pattern specificity
                    confidence = self._calculate_pattern_confidence(
                        category, match.group(), file_path, code_snippet
                    )
                    
                    # Enhanced finding with better metadata and secret value extraction
                    matched_text = match.group()
                    
                    # Extract the actual secret/vulnerability value for secrets
                    evidence = matched_text
                    if 'secret' in category.lower() or 'hardcode' in category.lower():
                        # Try to extract the actual secret value from the match
                        if '=' in matched_text and '"' in matched_text:
                            # Pattern like: String password = "secret123"
                            try:
                                secret_part = matched_text.split('=')[1].strip()
                                if secret_part.startswith('"') and secret_part.endswith('"'):
                                    evidence = f"Found hardcoded value: {secret_part}"
                                elif '"' in secret_part:
                                    quote_content = secret_part.split('"')[1]
                                    evidence = f"Found hardcoded value: \"{quote_content}\""
                            except:
                                pass
                    
                    # Create enhanced title with context
                    enhanced_title = f"{category.replace('_', ' ').title()}"
                    if 'secret' in category.lower():
                        enhanced_title = f"Hardcoded Secret Detected"
                    elif 'sql' in category.lower():
                        enhanced_title = f"SQL Injection Vulnerability"
                    elif 'backup' in category.lower():
                        enhanced_title = f"Backup Security Issue"
                    
                    finding = SecurityFinding(
                        id=f"pattern_{category}_{hash(match.group() + str(line_number))}",  # Include line number in hash for uniqueness
                        title=enhanced_title,
                        description=f"{pattern_info['description']}. Found in {file_path} at line {line_number}. Matched pattern: {matched_text[:50]}{'...' if len(matched_text) > 50 else ''}",
                        severity=pattern_info['severity'],
                        category=pattern_info['category'],
                        file_path=file_path,
                        line_number=line_number,
                        confidence=confidence,
                        code_snippet=code_snippet,
                        evidence=evidence,  # Include the actual matched evidence
                        pattern_type=category,  # Add pattern type for deduplication (FIXED PARAMETER NAME)
                        recommendations=self._get_recommendations(category),
                        cwe_id=self._get_cwe_ids(category)[0] if self._get_cwe_ids(category) else None,
                        masvs_control=self._get_masvs_control(category)
                    )
                    
                    findings.append(finding)
                    file_findings_count += 1
        
        # Log summary for files with findings
        if file_findings_count > 0:
            self.logger.debug(f"Static analysis: {os.path.basename(file_path)} -> {file_findings_count} findings")
        
        return findings
    
    def _should_exclude_file(self, file_path: str) -> bool:
        """Check if file should be excluded from analysis."""
        
        # Normalize path for pattern matching
        normalized_path = file_path.replace('\\', '/').lower()
        
        # CRITICAL FIX: Use comprehensive framework patterns to prioritize application code
        # These patterns match the logic in core/secret_extractor.py for consistency
        framework_patterns = {
            'com/google/android/gms/',      # Google Mobile Services (main issue)
            'com/google/firebase/',
            'androidx/',
            'android/support/', 
            'com/facebook/',
            'com/amazon/',
            'kotlin/',
            'kotlinx/',
            'org/apache/',
            'org/json/',
            'okhttp3/',
            'retrofit2/',
            'com/squareup/',
            'io/reactivex/',
            'rx/internal/',
            'dagger/',
            'javax/',
            'org/jetbrains/',
            'com/fasterxml/',
            'org/slf4j/',
            'ch/qos/logback/',
            '/R.java',
            '/BuildConfig.java',
            'test/',
            'androidTest/',
            'META-INF/',
            'com/facebook/react/',
            'io/flutter/',
            'com/github/'
        }
        
        # Check if file matches any framework pattern (skip these files)
        for pattern in framework_patterns:
            if pattern.lower() in normalized_path:
                self.logger.debug(f"Skipping framework file: {file_path} (matched pattern: {pattern})")
                return True
        
        # Check plugin's custom excluded patterns (for backward compatibility)
        for pattern in self.config.excluded_file_patterns:
            # Convert glob pattern to work with full paths
            if fnmatch.fnmatch(normalized_path, pattern.lower()) or fnmatch.fnmatch(os.path.basename(file_path).lower(), pattern.lower()):
                return True
            
            # Also check if pattern matches any part of the path
            if pattern.lower() in normalized_path:
                return True
        
        # Check included patterns (if specified)
        if hasattr(self.config, 'included_file_patterns') and self.config.included_file_patterns:
            for pattern in self.config.included_file_patterns:
                if fnmatch.fnmatch(normalized_path, pattern.lower()) or fnmatch.fnmatch(os.path.basename(file_path).lower(), pattern.lower()):
                    return False
            return True  # Not in included patterns
        
        return False
    
    def _calculate_pattern_confidence(self, category: str, match: str, file_path: str, code_snippet: str = None) -> float:
        """Calculate confidence score for a pattern match with optional ML enhancement."""
        # Create a dummy finding for confidence calculation
        try:
            from core.line_number_extractor import extract_line_number_from_match
            calculated_line = 1  # Fallback for dummy finding
        except ImportError:
            calculated_line = 1
        
        dummy_finding = SecurityFinding(
            id=f"pattern_{category}_{hash(match)}",
            title=f"{category.replace('_', ' ').title()} Pattern Match",
            description=f"Pattern match for {category}",
            severity=SeverityLevel.MEDIUM,
            category=FindingCategory.SECURITY_VULNERABILITY,
            file_path=file_path,
            line_number=calculated_line,
            evidence=match,
            pattern_type=category,
            confidence=0.0,  # Will be calculated
            code_snippet=code_snippet  # Add code snippet for ML analysis
        )
        
        # Try ML-enhanced confidence calculation first
        if self.ml_confidence_calculator and code_snippet:
            try:
                context = {
                    'pattern_category': category,
                    'match_value': match,
                    'file_extension': Path(file_path).suffix,
                    'file_type': self._determine_file_type(file_path)
                }
                ml_confidence = self.ml_confidence_calculator.calculate_confidence(dummy_finding, context)
                self.logger.debug(f"ML-enhanced confidence calculated: {ml_confidence:.2f} for {category}")
                return ml_confidence
            except Exception as e:
                self.logger.warning(f"ML confidence calculation failed, falling back to traditional: {e}")
        
        # Fallback to traditional confidence calculation
        if hasattr(self, 'confidence_calculator') and self.confidence_calculator:
            try:
                context = {
                    'pattern_category': category,
                    'match_value': match,
                    'file_extension': Path(file_path).suffix,
                    'file_type': self._determine_file_type(file_path)
                }
                return self.confidence_calculator.calculate_confidence(dummy_finding, context)
            except Exception as e:
                self.logger.warning(f"Traditional confidence calculation failed: {e}")
        
        # Fallback to simple confidence calculation
        base_confidence = 0.7
        
        # Adjust confidence based on file type
        if file_path.endswith('.java') or file_path.endswith('.kt'):
            base_confidence += 0.1
        elif file_path.endswith('.xml'):
            base_confidence += 0.05
        elif file_path.endswith('.properties'):
            base_confidence += 0.15
        
        # Adjust confidence based on match context
        if category == 'hardcoded_credentials':
            # Higher confidence for longer matches
            if len(match) > 20:
                base_confidence += 0.1
            # Lower confidence for test files
            if 'test' in file_path.lower():
                base_confidence -= 0.3
        
        elif category == 'crypto_weaknesses':
            # Higher confidence for actual algorithm usage
            if 'getInstance' in match:
                base_confidence += 0.1
        
        elif category == 'network_security':
            # Higher confidence for production code
            if 'debug' not in file_path.lower():
                base_confidence += 0.1
        
        return max(0.1, min(1.0, base_confidence))
    
    def _determine_file_type(self, file_path: str) -> str:
        """Determine the type of file for confidence calculation."""
        path = Path(file_path)
        extension = path.suffix.lower()
        
        if extension in ['.java', '.kt', '.scala']:
            return 'source_code'
        elif extension in ['.xml']:
            return 'manifest_files' if 'manifest' in path.name.lower() else 'resource_files'
        elif extension in ['.properties', '.config', '.ini']:
            return 'config_files'
        elif extension in ['.gradle', '.pro', '.cmake']:
            return 'build_files'
        elif extension in ['.md', '.txt', '.rst']:
            return 'documentation'
        elif 'test' in str(path):
            return 'test_files'
        else:
            return 'resource_files'
    
    def _get_recommendations(self, category: str) -> List[str]:
        """Get security recommendations for a vulnerability category."""
        recommendations = {
            'sql_injection': [
                'Use parameterized queries or prepared statements',
                'Validate and sanitize all user inputs',
                'Use ORM frameworks with built-in protection'
            ],
            'hardcoded_credentials': [
                'Store credentials securely using Android Keystore',
                'Use environment variables or secure configuration',
                'Implement proper credential management'
            ],
            'crypto_weaknesses': [
                'Use strong cryptographic algorithms (AES, SHA-256)',
                'Migrate from deprecated algorithms',
                'Follow OWASP cryptographic guidelines'
            ],
            'network_security': [
                'Implement proper certificate validation',
                'Use secure network configurations',
                'Enable certificate pinning'
            ],
            'logging_issues': [
                'Remove sensitive data from logs',
                'Use conditional logging for production',
                'Implement secure logging practices'
            ],
            'file_permissions': [
                'Use private file modes',
                'Implement proper access controls',
                'Validate file permissions'
            ],
            'intent_vulnerabilities': [
                'Validate intent data thoroughly',
                'Use explicit intents when possible',
                'Implement proper intent filtering'
            ]
        }
        
        return recommendations.get(category, ['Follow secure coding practices'])
    
    def _get_cwe_ids(self, category: str) -> List[str]:
        """Get CWE identifiers for a vulnerability category."""
        cwe_mapping = {
            'sql_injection': ['CWE-89'],
            'hardcoded_credentials': ['CWE-798', 'CWE-259'],
            'crypto_weaknesses': ['CWE-327', 'CWE-326'],
            'network_security': ['CWE-295', 'CWE-297'],
            'logging_issues': ['CWE-532', 'CWE-200'],
            'file_permissions': ['CWE-732', 'CWE-276'],
            'intent_vulnerabilities': ['CWE-926', 'CWE-925']
        }
        
        return cwe_mapping.get(category, [])
    
    def _get_masvs_control(self, category: str) -> str:
        """Get MASVS control mapping for a vulnerability category."""
        masvs_mapping = {
            'sql_injection': 'MSTG-CODE-8',
            'hardcoded_credentials': 'MSTG-CRYPTO-1',
            'crypto_weaknesses': 'MSTG-CRYPTO-4',
            'network_security': 'MSTG-NETWORK-1',
            'logging_issues': 'MSTG-STORAGE-3',
            'file_permissions': 'MSTG-STORAGE-2',
            'intent_vulnerabilities': 'MSTG-PLATFORM-1'
        }
        
        return masvs_mapping.get(category, 'MSTG-CODE-8')
    
    def analyze_directory(self, directory_path: str) -> List[SecurityFinding]:
        """Analyze all files in a directory for security vulnerabilities."""
        findings = []
        
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip binary files and large files
                    if not self._is_text_file(file_path):
                        continue
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            file_findings = self.analyze_file(file_path, content)
                            findings.extend(file_findings)
                    except Exception as e:
                        self.logger.warning(f"Failed to analyze file {file_path}: {e}")
                        continue
        
        except Exception as e:
            self.logger.error(f"Failed to analyze directory {directory_path}: {e}")
        
        return findings
    
    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is likely to be a text file."""
        text_extensions = {
            '.java', '.kt', '.xml', '.json', '.txt', '.properties',
            '.gradle', '.pro', '.cfg', '.conf', '.yaml', '.yml'
        }
        
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in text_extensions
    
    def get_analysis_summary(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Generate analysis summary from findings."""
        summary = {
            'total_findings': len(findings),
            'by_severity': {},
            'by_category': {},
            'high_confidence_findings': 0,
            'files_analyzed': set()
        }
        
        for finding in findings:
            # Count by severity
            severity = finding.severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by category
            category = finding.category.value
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
            
            # Count high confidence findings
            if finding.confidence >= 0.8:
                summary['high_confidence_findings'] += 1
            
            # Track analyzed files
            summary['files_analyzed'].add(finding.file_path)
        
        summary['files_analyzed'] = len(summary['files_analyzed'])
        
        return summary
    
    def get_ml_statistics(self) -> Dict[str, Any]:
        """Get ML-enhanced confidence calculation statistics."""
        if self.ml_confidence_calculator:
            ml_stats = self.ml_confidence_calculator.get_statistics()
            return {
                'ml_confidence_enabled': True,
                **ml_stats
            }
        else:
            return {
                'ml_confidence_enabled': False,
                'ml_available': ML_ENHANCED_CONFIDENCE_AVAILABLE,
                'reason': 'ML confidence calculator not initialized'
            }