"""
Cloud Service Validator for AODS Framework.

This module provides comprehensive validation of cloud service configurations
in Android applications, specifically targeting patterns found in Android
security testing scenarios.

Features:
- SQLite database security validation
- Firebase configuration analysis
- ROT47 cipher detection and analysis
- AWS S3 bucket credentials validation
- Cloud service security assessment

This validator specializes in identifying applications that store cloud service
credentials insecurely or use weak encoding mechanisms to obfuscate cloud
service configurations.
"""

import base64
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from rich.text import Text
from rich.table import Table
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

logger = logging.getLogger(__name__)

class CloudServiceValidator:
    """
    Comprehensive cloud service validator for Android applications.
    
    This validator identifies and analyzes cloud service configurations in Android
    applications, with particular focus on insecure credential storage, weak
    encoding mechanisms, and misconfigurations that could lead to security
    vulnerabilities.
    """
    
    def __init__(self, apk_context=None):
        """
        Initialize the cloud service validator.
        
        Args:
            apk_context: APK context object containing application metadata
        """
        self.apk_context = apk_context
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.console = Console()
        
        # Cloud service patterns
        self.cloud_service_patterns = {
            'firebase': {
                'description': 'Firebase configuration analysis',
                'patterns': [
                    r'firebase\.googleapis\.com',
                    r'firebaseio\.com',
                    r'firebase-adminsdk',
                    r'google-services\.json',
                    r'FirebaseApp\.initializeApp',
                    r'FirebaseDatabase\.getInstance',
                    r'databaseURL',
                    r'projectId',
                    r'storageBucket',
                    r'messagingSenderId',
                    r'appId'
                ],
                'security_indicators': [
                    'API_KEY',
                    'DATABASE_URL',
                    'STORAGE_BUCKET',
                    'PROJECT_ID',
                    'AUTH_DOMAIN'
                ]
            },
            'aws': {
                'description': 'AWS S3 bucket credentials validation',
                'patterns': [
                    r'amazonaws\.com',
                    r's3\.amazonaws\.com',
                    r'AWSAccessKeyId',
                    r'AWSSecretKey',
                    r'aws_access_key_id',
                    r'aws_secret_access_key',
                    r'region',
                    r'bucket',
                    r'S3Client',
                    r'AmazonS3Client'
                ],
                'credential_patterns': [
                    r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
                    r'[A-Za-z0-9/+=]{40}',  # AWS Secret Access Key
                    r'us-[a-z]+-[0-9]',  # AWS regions
                    r'eu-[a-z]+-[0-9]',
                    r'ap-[a-z]+-[0-9]'
                ]
            },
            'google_cloud': {
                'description': 'Google Cloud Platform configuration',
                'patterns': [
                    r'googleapis\.com',
                    r'gcloud',
                    r'service_account',
                    r'client_email',
                    r'private_key',
                    r'project_id',
                    r'auth_uri',
                    r'token_uri',
                    r'client_x509_cert_url'
                ]
            },
            'azure': {
                'description': 'Microsoft Azure configuration',
                'patterns': [
                    r'azure\.com',
                    r'windows\.net',
                    r'storage\.azure\.com',
                    r'blob\.core\.windows\.net',
                    r'DefaultEndpointsProtocol',
                    r'AccountName',
                    r'AccountKey',
                    r'EndpointSuffix'
                ]
            }
        }
        
        # ROT47 decoding table
        self.rot47_decode_table = {}
        for i in range(33, 127):
            self.rot47_decode_table[chr(i)] = chr(33 + (i - 33 + 47) % 94)
        
        # Analysis results
        self.cloud_service_findings = []
        self.credential_findings = []
        self.configuration_issues = []
        self.security_recommendations = []
        
        # Statistics
        self.analysis_stats = {
            'cloud_services_found': 0,
            'credentials_found': 0,
            'security_issues': 0,
            'configurations_analyzed': 0
        }
        
        self.logger.info("Cloud Service Validator initialized")

    def validate_cloud_services(self, deep_mode: bool = False) -> Tuple[str, Text]:
        """
        Comprehensive cloud service validation.

        Args:
            deep_mode: Whether to perform deep validation

        Returns:
            Tuple of (validation_title, validation_results)
        """
        self.logger.info("Starting cloud service validation")
        
        try:
            # Initialize progress tracking
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # Validation phases
                pattern_task = progress.add_task("Analyzing cloud service patterns", total=100)
                credential_task = progress.add_task("Validating credentials", total=100)
                config_task = progress.add_task("Checking configurations", total=100)
                security_task = progress.add_task("Assessing security", total=100)
                
                # Phase 1: Pattern analysis
                progress.update(pattern_task, advance=20)
                self._analyze_cloud_service_patterns()
                progress.update(pattern_task, advance=60)
                
                # Phase 2: Credential validation
                progress.update(credential_task, advance=25)
                self._validate_cloud_credentials()
                progress.update(credential_task, advance=75)
                
                # Phase 3: Configuration checking
                progress.update(config_task, advance=30)
                self._check_cloud_configurations()
                progress.update(config_task, advance=70)
                
                # Phase 4: Security assessment
                progress.update(security_task, advance=40)
                self._assess_cloud_security()
                progress.update(security_task, advance=60)
                
                # Complete validation
                progress.update(pattern_task, completed=100)
                progress.update(credential_task, completed=100)
                progress.update(config_task, completed=100)
                progress.update(security_task, completed=100)
            
            # Generate comprehensive report
            report = self._generate_cloud_service_report()
            
            self.logger.info(f"Cloud service validation completed. Found {len(self.cloud_service_findings)} services")
            
            return "Cloud Service Validation", report
            
        except Exception as e:
            self.logger.error(f"Cloud service validation failed: {e}")
            return "Cloud Service Validation", Text(f"Validation failed: {str(e)}", style="red")

    def _analyze_cloud_service_patterns(self):
        """Analyze cloud service patterns in the application."""
        self.logger.debug("Analyzing cloud service patterns")
        
        try:
            if not self.apk_context:
                self.logger.warning("No APK context available for pattern analysis")
                return
            
            # Analyze source files
            source_files = getattr(self.apk_context, 'source_files', [])
            for file_path in source_files:
                self._analyze_file_for_cloud_services(file_path)
            
            # Analyze configuration files
            config_files = getattr(self.apk_context, 'config_files', [])
            for file_path in config_files:
                self._analyze_config_file(file_path)
            
            # Analyze strings
            strings_data = getattr(self.apk_context, 'strings', [])
            self._analyze_strings_for_cloud_services(strings_data)
            
            # Analyze databases
            db_files = getattr(self.apk_context, 'database_files', [])
            for db_path in db_files:
                self._analyze_database_for_cloud_data(db_path)
            
            self.analysis_stats['cloud_services_found'] = len(self.cloud_service_findings)

        except Exception as e:
            self.logger.error(f"Cloud service pattern analysis failed: {e}")

    def _analyze_file_for_cloud_services(self, file_path: str):
        """Analyze individual file for cloud service patterns."""
        try:
            if not os.path.exists(file_path):
                return
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check each cloud service pattern
            for service_type, service_data in self.cloud_service_patterns.items():
                for pattern in service_data['patterns']:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    
                    for match in matches:
                        finding = {
                            'service_type': service_type,
                            'pattern': pattern,
                            'match': match.group(),
                            'file_path': file_path,
                            'line': content[:match.start()].count('\n') + 1,
                            'context': self._extract_context(content, match.start(), match.end()),
                            'confidence': 0.8,
                            'description': service_data['description']
                        }
                        
                        self.cloud_service_findings.append(finding)
                        
        except Exception as e:
            self.logger.error(f"File cloud service analysis failed for {file_path}: {e}")

    def _analyze_config_file(self, file_path: str):
        """Analyze configuration file for cloud services."""
        try:
            if not os.path.exists(file_path):
                return
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for JSON configuration
            if file_path.endswith('.json'):
                try:
                    config_data = json.loads(content)
                    self._analyze_json_config(config_data, file_path)
                except json.JSONDecodeError:
                    pass
            
            # Check for XML configuration
            elif file_path.endswith('.xml'):
                self._analyze_xml_config(content, file_path)
            
            # Check for properties files
            elif file_path.endswith('.properties'):
                self._analyze_properties_config(content, file_path)
                
        except Exception as e:
            self.logger.error(f"Config file analysis failed for {file_path}: {e}")

    def _analyze_json_config(self, config_data: Dict[str, Any], file_path: str):
        """Analyze JSON configuration for cloud services."""
        try:
            # Check for Firebase configuration
            if 'firebase' in str(config_data).lower():
                finding = {
                    'service_type': 'firebase',
                    'pattern': 'firebase_json_config',
                    'match': 'Firebase JSON configuration',
                    'file_path': file_path,
                    'config_data': config_data,
                    'confidence': 0.9,
                    'description': 'Firebase JSON configuration file'
                }
                self.cloud_service_findings.append(finding)
            
            # Check for AWS configuration
            aws_keys = ['aws_access_key_id', 'aws_secret_access_key', 'region', 'bucket']
            if any(key in str(config_data).lower() for key in aws_keys):
                finding = {
                    'service_type': 'aws',
                    'pattern': 'aws_json_config',
                    'match': 'AWS JSON configuration',
                    'file_path': file_path,
                    'config_data': config_data,
                    'confidence': 0.9,
                    'description': 'AWS JSON configuration file'
                }
                self.cloud_service_findings.append(finding)
                
        except Exception as e:
            self.logger.error(f"JSON config analysis failed: {e}")

    def _analyze_xml_config(self, content: str, file_path: str):
        """Analyze XML configuration for cloud services."""
        try:
            # Check for cloud service XML patterns
            xml_patterns = [
                (r'<firebase[^>]*>', 'firebase'),
                (r'<aws[^>]*>', 'aws'),
                (r'<google-cloud[^>]*>', 'google_cloud'),
                (r'<azure[^>]*>', 'azure')
            ]
            
            for pattern, service_type in xml_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    finding = {
                        'service_type': service_type,
                        'pattern': pattern,
                        'match': match.group(),
                        'file_path': file_path,
                        'line': content[:match.start()].count('\n') + 1,
                        'context': self._extract_context(content, match.start(), match.end()),
                        'confidence': 0.8,
                        'description': f'{service_type} XML configuration'
                    }
                    
                    self.cloud_service_findings.append(finding)

        except Exception as e:
            self.logger.error(f"XML config analysis failed: {e}")

    def _analyze_properties_config(self, content: str, file_path: str):
        """Analyze properties configuration for cloud services."""
        try:
            # Check for cloud service properties
            properties_patterns = [
                (r'firebase\.[^=]*=', 'firebase'),
                (r'aws\.[^=]*=', 'aws'),
                (r'google\.[^=]*=', 'google_cloud'),
                (r'azure\.[^=]*=', 'azure')
            ]
            
            for pattern, service_type in properties_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    finding = {
                        'service_type': service_type,
                        'pattern': pattern,
                        'match': match.group(),
                        'file_path': file_path,
                        'line': content[:match.start()].count('\n') + 1,
                        'context': self._extract_context(content, match.start(), match.end()),
                        'confidence': 0.7,
                        'description': f'{service_type} properties configuration'
                    }
                    
                    self.cloud_service_findings.append(finding)

        except Exception as e:
            self.logger.error(f"Properties config analysis failed: {e}")

    def _analyze_strings_for_cloud_services(self, strings_data: List[str]):
        """Analyze strings for cloud service patterns."""
        try:
            for string_value in strings_data:
                # Check for Firebase URLs
                if 'firebase' in string_value.lower():
                    # Check for ROT47 encoded Firebase URLs
                    if self._is_rot47_encoded(string_value):
                        decoded_url = self._decode_rot47(string_value)
                        if decoded_url and 'firebase' in decoded_url.lower():
                            finding = {
                                'service_type': 'firebase',
                                'pattern': 'rot47_firebase_url',
                                'match': string_value,
                                'decoded': decoded_url,
                                'source': 'strings',
                                'confidence': 0.9,
                                'description': 'ROT47 encoded Firebase URL detected'
                            }
                            self.cloud_service_findings.append(finding)
                
                # Check for AWS credentials
                aws_patterns = self.cloud_service_patterns['aws']['credential_patterns']
                for pattern in aws_patterns:
                    if re.search(pattern, string_value):
                        finding = {
                            'service_type': 'aws',
                            'pattern': pattern,
                            'match': string_value,
                            'source': 'strings',
                            'confidence': 0.8,
                            'description': 'AWS credential pattern detected'
                        }
                        self.cloud_service_findings.append(finding)
                
                # Check for other cloud service URLs
                cloud_url_patterns = [
                    (r'https?://[^/]*googleapis\.com', 'google_cloud'),
                    (r'https?://[^/]*azure\.com', 'azure'),
                    (r'https?://[^/]*amazonaws\.com', 'aws')
                ]
                
                for pattern, service_type in cloud_url_patterns:
                    if re.search(pattern, string_value, re.IGNORECASE):
                        finding = {
                            'service_type': service_type,
                            'pattern': pattern,
                            'match': string_value,
                            'source': 'strings',
                            'confidence': 0.7,
                            'description': f'{service_type} URL detected'
                        }
                        self.cloud_service_findings.append(finding)
                        
        except Exception as e:
            self.logger.error(f"String cloud service analysis failed: {e}")

    def _analyze_database_for_cloud_data(self, db_path: str):
        """Analyze database for cloud service data."""
        try:
            if not os.path.exists(db_path):
                return
            
            # Connect to SQLite database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                
                # Skip system tables
                if table_name.startswith('sqlite_'):
                    continue
                
                try:
                    # Get table contents
                    cursor.execute(f"SELECT * FROM {table_name}")
                    rows = cursor.fetchall()
                    
                    # Get column names
                    cursor.execute(f"PRAGMA table_info({table_name})")
                    columns = [col[1] for col in cursor.fetchall()]
                    
                    # Check for cloud service data
                    for row in rows:
                        for i, value in enumerate(row):
                            if value and isinstance(value, str):
                                # Check for cloud service patterns
                                for service_type, service_data in self.cloud_service_patterns.items():
                                    for pattern in service_data['patterns']:
                                        if re.search(pattern, value, re.IGNORECASE):
                                            finding = {
                                                'service_type': service_type,
                                                'pattern': pattern,
                                                'match': value,
                                                'database': db_path,
                                                'table': table_name,
                                                'column': columns[i] if i < len(columns) else 'unknown',
                                                'confidence': 0.8,
                                                'description': f'{service_type} data in database'
                                            }
                                            self.cloud_service_findings.append(finding)
                
                except sqlite3.Error as e:
                    self.logger.debug(f"Database table analysis failed for {table_name}: {e}")
                    continue
            
            conn.close()

        except Exception as e:
            self.logger.error(f"Database cloud service analysis failed for {db_path}: {e}")

    def _is_rot47_encoded(self, text: str) -> bool:
        """Check if text is ROT47 encoded."""
        try:
            # Check if text contains ROT47 character range
            rot47_chars = sum(1 for c in text if 33 <= ord(c) <= 126)
            return rot47_chars > len(text) * 0.8  # 80% threshold
        except:
            return False

    def _decode_rot47(self, text: str) -> str:
        """Decode ROT47 encoded text."""
        try:
            decoded = ""
            for char in text:
                if char in self.rot47_decode_table:
                    decoded += self.rot47_decode_table[char]
                else:
                    decoded += char
            return decoded
        except:
            return text

    def _extract_context(self, content: str, start: int, end: int, context_size: int = 100) -> str:
        """Extract context around a match."""
        try:
            context_start = max(0, start - context_size)
            context_end = min(len(content), end + context_size)
            return content[context_start:context_end].strip()
        except:
            return ""

    def _validate_cloud_credentials(self):
        """Validate cloud service credentials."""
        self.logger.debug("Validating cloud credentials")
        
        try:
            for finding in self.cloud_service_findings:
                service_type = finding['service_type']
                match = finding['match']
                
                # Validate based on service type
                if service_type == 'aws':
                    self._validate_aws_credentials(finding)
                elif service_type == 'firebase':
                    self._validate_firebase_credentials(finding)
                elif service_type == 'google_cloud':
                    self._validate_google_cloud_credentials(finding)
                elif service_type == 'azure':
                    self._validate_azure_credentials(finding)
                    
        except Exception as e:
            self.logger.error(f"Credential validation failed: {e}")

    def _validate_aws_credentials(self, finding: Dict[str, Any]):
        """Validate AWS credentials."""
        try:
            match = finding['match']
            
            # Check for AWS Access Key ID pattern
            if re.match(r'AKIA[0-9A-Z]{16}', match):
                credential = {
                    'service_type': 'aws',
                    'credential_type': 'access_key_id',
                    'value': match,
                    'validity': 'format_valid',
                    'security_risk': 'HIGH',
                    'description': 'AWS Access Key ID detected'
                }
                self.credential_findings.append(credential)
                self.analysis_stats['credentials_found'] += 1
            
            # Check for AWS Secret Access Key pattern
            elif re.match(r'[A-Za-z0-9/+=]{40}', match):
                credential = {
                    'service_type': 'aws',
                    'credential_type': 'secret_access_key',
                    'value': match,
                    'validity': 'format_valid',
                    'security_risk': 'CRITICAL',
                    'description': 'AWS Secret Access Key detected'
                }
                self.credential_findings.append(credential)
                self.analysis_stats['credentials_found'] += 1
                
        except Exception as e:
            self.logger.error(f"AWS credential validation failed: {e}")

    def _validate_firebase_credentials(self, finding: Dict[str, Any]):
        """Validate Firebase credentials."""
        try:
            match = finding['match']
            
            # Check for Firebase configuration
            if 'firebase' in match.lower():
                credential = {
                    'service_type': 'firebase',
                    'credential_type': 'configuration',
                    'value': match,
                    'validity': 'configuration_detected',
                    'security_risk': 'MEDIUM',
                    'description': 'Firebase configuration detected'
                }
                self.credential_findings.append(credential)
                self.analysis_stats['credentials_found'] += 1
                
        except Exception as e:
            self.logger.error(f"Firebase credential validation failed: {e}")

    def _validate_google_cloud_credentials(self, finding: Dict[str, Any]):
        """Validate Google Cloud credentials."""
        try:
            match = finding['match']
            
            # Check for service account patterns
            if 'service_account' in match.lower():
                credential = {
                    'service_type': 'google_cloud',
                    'credential_type': 'service_account',
                    'value': match,
                    'validity': 'service_account_detected',
                    'security_risk': 'HIGH',
                    'description': 'Google Cloud service account detected'
                }
                self.credential_findings.append(credential)
                self.analysis_stats['credentials_found'] += 1
                
        except Exception as e:
            self.logger.error(f"Google Cloud credential validation failed: {e}")

    def _validate_azure_credentials(self, finding: Dict[str, Any]):
        """Validate Azure credentials."""
        try:
            match = finding['match']
            
            # Check for Azure storage account
            if 'accountkey' in match.lower():
                credential = {
                    'service_type': 'azure',
                    'credential_type': 'storage_account_key',
                    'value': match,
                    'validity': 'account_key_detected',
                    'security_risk': 'HIGH',
                    'description': 'Azure storage account key detected'
                }
                self.credential_findings.append(credential)
                self.analysis_stats['credentials_found'] += 1
                
        except Exception as e:
            self.logger.error(f"Azure credential validation failed: {e}")

    def _check_cloud_configurations(self):
        """Check cloud service configurations."""
        self.logger.debug("Checking cloud configurations")
        
        try:
            # Group findings by service type
            service_groups = {}
            for finding in self.cloud_service_findings:
                service_type = finding['service_type']
                if service_type not in service_groups:
                    service_groups[service_type] = []
                service_groups[service_type].append(finding)
            
            # Check each service type
            for service_type, findings in service_groups.items():
                config_issue = {
                    'service_type': service_type,
                    'findings_count': len(findings),
                    'configuration_issues': self._identify_config_issues(service_type, findings),
                    'security_implications': self._assess_config_security(service_type, findings)
                }
                
                self.configuration_issues.append(config_issue)
                self.analysis_stats['configurations_analyzed'] += 1
                
        except Exception as e:
            self.logger.error(f"Configuration checking failed: {e}")

    def _identify_config_issues(self, service_type: str, findings: List[Dict[str, Any]]) -> List[str]:
        """Identify configuration issues for service type."""
        issues = []
        
        if service_type == 'firebase':
            # Check for hardcoded Firebase URLs
            if any('firebase' in f['match'].lower() for f in findings):
                issues.append("Hardcoded Firebase URLs detected")
            
            # Check for ROT47 encoded URLs
            if any('rot47' in f.get('pattern', '') for f in findings):
                issues.append("ROT47 encoded Firebase URLs (weak obfuscation)")
        
        elif service_type == 'aws':
            # Check for hardcoded credentials
            if any('AKIA' in f['match'] for f in findings):
                issues.append("Hardcoded AWS Access Key ID")
            
            # Check for secret keys
            if any(len(f['match']) == 40 for f in findings):
                issues.append("Potential AWS Secret Access Key")
        
        elif service_type == 'google_cloud':
            # Check for service account keys
            if any('service_account' in f['match'].lower() for f in findings):
                issues.append("Service account configuration detected")
        
        elif service_type == 'azure':
            # Check for storage account keys
            if any('accountkey' in f['match'].lower() for f in findings):
                issues.append("Azure storage account key detected")
        
        return issues

    def _assess_config_security(self, service_type: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess security implications of configurations."""
        security_assessment = {
            'risk_level': 'MEDIUM',
            'issues': [],
            'recommendations': []
        }
        
        if service_type == 'aws':
            if any('AKIA' in f['match'] for f in findings):
                security_assessment['risk_level'] = 'CRITICAL'
                security_assessment['issues'].append('AWS credentials hardcoded in application')
                security_assessment['recommendations'].append('Move credentials to secure storage')
        
        elif service_type == 'firebase':
            if any('rot47' in f.get('pattern', '') for f in findings):
                security_assessment['risk_level'] = 'HIGH'
                security_assessment['issues'].append('Weak obfuscation used for Firebase URLs')
                security_assessment['recommendations'].append('Use proper encryption instead of ROT47')
        
        return security_assessment

    def _assess_cloud_security(self):
        """Assess overall cloud security."""
        self.logger.debug("Assessing cloud security")
        
        try:
            # Generate security recommendations
            recommendations = []
            
            # Check for credential findings
            if self.credential_findings:
                recommendations.append("Remove hardcoded cloud service credentials")
                recommendations.append("Use secure credential storage mechanisms")
                recommendations.append("Implement proper authentication flows")
                self.analysis_stats['security_issues'] += len(self.credential_findings)
            
            # Check for configuration issues
            if self.configuration_issues:
                recommendations.append("Review cloud service configurations")
                recommendations.append("Implement proper access controls")
                recommendations.append("Use environment-specific configurations")
                self.analysis_stats['security_issues'] += len(self.configuration_issues)
            
            # Check for encoding issues
            rot47_findings = [f for f in self.cloud_service_findings if 'rot47' in f.get('pattern', '')]
            if rot47_findings:
                recommendations.append("Replace ROT47 encoding with proper encryption")
                recommendations.append("Use industry-standard obfuscation techniques")
                self.analysis_stats['security_issues'] += len(rot47_findings)
            
            self.security_recommendations = recommendations

        except Exception as e:
            self.logger.error(f"Cloud security assessment failed: {e}")

    def _generate_cloud_service_report(self) -> Text:
        """Generate comprehensive cloud service validation report."""
        report = Text()
        
        # Header
        report.append("☁️ Cloud Service Validation Report\n", style="bold blue")
        report.append("=" * 50 + "\n\n", style="blue")
        
        # Summary statistics
        report.append("📊 Validation Summary:\n", style="bold green")
        report.append(f"• Cloud services found: {self.analysis_stats['cloud_services_found']}\n", style="green")
        report.append(f"• Credentials found: {self.analysis_stats['credentials_found']}\n", style="yellow")
        report.append(f"• Security issues: {self.analysis_stats['security_issues']}\n", style="red")
        report.append(f"• Configurations analyzed: {self.analysis_stats['configurations_analyzed']}\n", style="green")
        report.append("\n")
        
        # Cloud service findings
        if self.cloud_service_findings:
            report.append("🔍 Cloud Service Findings:\n", style="bold yellow")
            service_counts = {}
            for finding in self.cloud_service_findings:
                service_type = finding['service_type']
                service_counts[service_type] = service_counts.get(service_type, 0) + 1
            
            for service_type, count in service_counts.items():
                report.append(f"• {service_type.upper()}: {count} findings\n", style="yellow")
            report.append("\n")
        
        # Credential findings
        if self.credential_findings:
            report.append("🔑 Credential Findings:\n", style="bold red")
            for i, credential in enumerate(self.credential_findings, 1):
                risk_color = {
                    'CRITICAL': 'red',
                    'HIGH': 'yellow',
                    'MEDIUM': 'cyan'
                }.get(credential['security_risk'], 'white')
                
                report.append(f"{i}. {credential['description']}\n", style=risk_color)
                report.append(f"   Service: {credential['service_type']}\n", style="dim")
                report.append(f"   Type: {credential['credential_type']}\n", style="dim")
                report.append(f"   Risk: {credential['security_risk']}\n", style=risk_color)
                report.append("\n")
        
        # Configuration issues
        if self.configuration_issues:
            report.append("⚙️ Configuration Issues:\n", style="bold cyan")
            for issue in self.configuration_issues:
                report.append(f"• {issue['service_type'].upper()}: {issue['findings_count']} findings\n", style="cyan")
                for config_issue in issue['configuration_issues']:
                    report.append(f"  - {config_issue}\n", style="dim")
                report.append("\n")
        
        # Security recommendations
        if self.security_recommendations:
            report.append("🛡️ Security Recommendations:\n", style="bold green")
            for rec in self.security_recommendations:
                report.append(f"• {rec}\n", style="green")
        else:
            report.append("🛡️ Security Recommendations:\n", style="bold green")
            report.append("• No critical cloud service issues detected\n", style="green")
            report.append("• Continue monitoring for credential exposure\n", style="green")
        
        return report

    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get comprehensive analysis statistics."""
        return {
            'cloud_services_found': self.analysis_stats['cloud_services_found'],
            'credentials_found': self.analysis_stats['credentials_found'],
            'security_issues': self.analysis_stats['security_issues'],
            'configurations_analyzed': self.analysis_stats['configurations_analyzed'],
            'service_types': list(set(f['service_type'] for f in self.cloud_service_findings)),
            'credential_types': list(set(c['credential_type'] for c in self.credential_findings)),
            'affected_files': len(set(f.get('file_path', 'unknown') for f in self.cloud_service_findings)),
            'analysis_quality': 'high' if self.analysis_stats['cloud_services_found'] > 0 else 'medium'
        }

    def export_findings(self, output_file: str) -> bool:
        """Export findings to JSON file."""
        try:
            export_data = {
                'timestamp': time.time(),
                'analysis_type': 'cloud_service_validation',
                'cloud_service_findings': self.cloud_service_findings,
                'credential_findings': self.credential_findings,
                'configuration_issues': self.configuration_issues,
                'security_recommendations': self.security_recommendations,
                'statistics': self.get_analysis_statistics()
            }
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Findings exported to: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export findings: {e}")
            return False

# Enhanced functions for plugin integration

def validate_cloud_services_comprehensive(apk_context, deep_mode: bool = False) -> Tuple[str, Text]:
    """
    Comprehensive cloud service validation function.
    
    Args:
        apk_context: APK context object
        deep_mode: Whether to perform deep validation
        
    Returns:
        Tuple of (validation_title, validation_results)
    """
    validator = CloudServiceValidator(apk_context)
    return validator.validate_cloud_services(deep_mode)

def detect_cloud_services(apk_context) -> List[Dict[str, Any]]:
    """
    Detect cloud services in APK.
    
    Args:
        apk_context: APK context object
        
    Returns:
        List of cloud service findings
    """
    validator = CloudServiceValidator(apk_context)
    validator._analyze_cloud_service_patterns()
    return validator.cloud_service_findings

def validate_cloud_credentials(apk_context) -> List[Dict[str, Any]]:
    """
    Validate cloud credentials in APK.
    
    Args:
        apk_context: APK context object
        
    Returns:
        List of credential findings
    """
    validator = CloudServiceValidator(apk_context)
    validator._analyze_cloud_service_patterns()
    validator._validate_cloud_credentials()
    return validator.credential_findings
