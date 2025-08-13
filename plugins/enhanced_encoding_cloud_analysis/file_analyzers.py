"""
File Analyzers Module

This module handles analysis of different file types including source code files,
resource files, configuration files, and native binary files with specialized
analysis methods for each type.
"""

import os
import logging
import mimetypes
from typing import List, Dict, Optional, Set, Tuple, Generator
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from .data_structures import (
    FileAnalysisResult, EncodingFinding, CipherFinding, CloudServiceFinding,
    FileType, AnalysisConfiguration, EncodingCloudAnalysisError
)
from .encoding_analyzer import AdvancedEncodingAnalyzer
from .cloud_service_analyzer import CloudServiceAnalyzer

logger = logging.getLogger(__name__)

class FileTypeDetector:
    """Utility class for detecting and categorizing file types."""
    
    # File extension mappings
    SOURCE_CODE_EXTENSIONS = {
        '.java', '.kt', '.js', '.ts', '.dart', '.py', '.cpp', '.c', '.h',
        '.swift', '.m', '.mm', '.scala', '.go', '.rs'
    }
    
    RESOURCE_EXTENSIONS = {
        '.xml', '.json', '.yaml', '.yml', '.properties', '.txt', '.csv',
        '.html', '.htm', '.css', '.scss', '.less'
    }
    
    CONFIG_EXTENSIONS = {
        '.conf', '.config', '.ini', '.cfg', '.toml', '.env', '.plist'
    }
    
    NATIVE_EXTENSIONS = {
        '.so', '.a', '.dylib', '.dll', '.bin', '.dex', '.odex', '.art'
    }
    
    @classmethod
    def detect_file_type(cls, file_path: str) -> FileType:
        """
        Detect the type of file based on extension and path.
        
        Args:
            file_path: Path to the file
            
        Returns:
            FileType enum value
        """
        path = Path(file_path)
        extension = path.suffix.lower()
        
        # Special cases based on filename
        if path.name.lower() == 'androidmanifest.xml':
            return FileType.MANIFEST
        elif path.name.lower() == 'strings.xml':
            return FileType.STRINGS_XML
        
        # Check extension mappings
        if extension in cls.SOURCE_CODE_EXTENSIONS:
            return FileType.SOURCE_CODE
        elif extension in cls.RESOURCE_EXTENSIONS:
            return FileType.RESOURCE_FILE
        elif extension in cls.CONFIG_EXTENSIONS:
            return FileType.CONFIG_FILE
        elif extension in cls.NATIVE_EXTENSIONS:
            return FileType.NATIVE_FILE
        
        # Check MIME type for additional detection
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            if mime_type.startswith('text/'):
                return FileType.RESOURCE_FILE
            elif 'application/octet-stream' in mime_type:
                return FileType.BINARY
        
        return FileType.OTHER
    
    @classmethod
    def is_binary_file(cls, file_path: str) -> bool:
        """Check if a file is binary."""
        try:
            with open(file_path, 'rb') as f:
                # Read first 1024 bytes to check for binary content
                chunk = f.read(1024)
                # Check for null bytes which indicate binary content
                return b'\x00' in chunk
        except Exception:
            return True  # Assume binary if we can't read it

class SourceCodeAnalyzer:
    """Specialized analyzer for source code files."""
    
    def __init__(self, encoding_analyzer: AdvancedEncodingAnalyzer, 
                 cloud_analyzer: CloudServiceAnalyzer):
        self.encoding_analyzer = encoding_analyzer
        self.cloud_analyzer = cloud_analyzer
        
        # Source code specific patterns
        self.source_patterns = {
            'android_security': [
                'SharedPreferences', 'getSharedPreferences', 'PreferenceManager',
                'SQLiteDatabase', 'ContentProvider', 'BroadcastReceiver',
                'IntentFilter', 'PendingIntent', 'WebView', 'HttpsURLConnection'
            ],
            'encryption_apis': [
                'javax.crypto', 'Cipher.getInstance', 'KeyGenerator',
                'MessageDigest', 'SecretKeySpec', 'KeyPairGenerator'
            ],
            'network_apis': [
                'HttpURLConnection', 'OkHttpClient', 'Retrofit',
                'URLConnection', 'Socket', 'SSLContext'
            ]
        }
    
    def analyze_source_file(self, file_path: str, content: str, 
                           config: AnalysisConfiguration) -> FileAnalysisResult:
        """
        Analyze a source code file for encoding and cloud service issues.
        
        Args:
            file_path: Path to the source file
            content: File content
            config: Analysis configuration
            
        Returns:
            FileAnalysisResult with findings
        """
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=FileType.SOURCE_CODE,
            content_size=len(content)
        )
        
        try:
            # Check if file contains relevant patterns
            if not self._contains_relevant_patterns(content):
                logger.debug(f"Skipping {file_path} - no relevant patterns")
                return result
            
            # Encoding analysis
            if config.analyze_source_files:
                encoding_findings = self.encoding_analyzer.analyze_content(
                    content, f"source:{Path(file_path).name}", FileType.SOURCE_CODE
                )
                result.encoding_findings.extend(encoding_findings)
            
            # Cloud service analysis
            cloud_findings = self.cloud_analyzer.analyze_cloud_services(
                content, f"source:{Path(file_path).name}", FileType.SOURCE_CODE
            )
            result.cloud_findings.extend(cloud_findings)
            
            # Source code specific analysis
            self._analyze_android_specific_patterns(content, result)
            self._analyze_encryption_usage(content, result)
            self._analyze_network_security(content, result)
            
        except Exception as e:
            result.analysis_successful = False
            result.error_message = f"Error analyzing source file: {e}"
            logger.error(f"Error analyzing source file {file_path}: {e}")
        
        return result
    
    def _contains_relevant_patterns(self, content: str) -> bool:
        """Check if content contains patterns worth analyzing."""
        # Quick check for encoding patterns
        encoding_indicators = ['base64', 'encode', 'decode', 'cipher', 'crypt', 'hash']
        cloud_indicators = ['firebase', 'aws', 's3', 'azure', 'api', 'http']
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in encoding_indicators + cloud_indicators)
    
    def _analyze_android_specific_patterns(self, content: str, result: FileAnalysisResult):
        """Analyze Android-specific security patterns in source code."""
        for pattern_name, patterns in self.source_patterns.items():
            for pattern in patterns:
                if pattern in content:
                    # Create appropriate findings based on pattern type
                    result.vulnerabilities.append({
                        'type': 'source_code_pattern',
                        'description': f'Source code pattern detected: {pattern}',
                        'severity': 'medium',
                        'pattern': pattern
                    })
    
    def _analyze_encryption_usage(self, content: str, result: FileAnalysisResult):
        """Analyze encryption API usage in source code."""
        # Check for weak encryption patterns
        weak_patterns = ['DES', 'MD5', 'SHA1', 'RC4']
        for pattern in weak_patterns:
            if pattern in content:
                # Create cipher findings for weak encryption
                result.vulnerabilities.append({
                    'type': 'weak_encryption',
                    'description': f'Weak encryption algorithm detected: {pattern}',
                    'severity': 'high',
                    'pattern': pattern
                })
    
    def _analyze_network_security(self, content: str, result: FileAnalysisResult):
        """Analyze network security patterns in source code."""
        # Check for insecure network configurations
        insecure_patterns = ['TrustAllCerts', 'HostnameVerifier', 'TrustManager']
        for pattern in insecure_patterns:
            if pattern in content:
                # Create security findings
                result.vulnerabilities.append({
                    'type': 'insecure_network_config',
                    'description': f'Insecure network configuration detected: {pattern}',
                    'severity': 'high',
                    'pattern': pattern
                })

class ResourceFileAnalyzer:
    """Specialized analyzer for resource files (XML, JSON, etc.)."""
    
    def __init__(self, encoding_analyzer: AdvancedEncodingAnalyzer, 
                 cloud_analyzer: CloudServiceAnalyzer):
        self.encoding_analyzer = encoding_analyzer
        self.cloud_analyzer = cloud_analyzer
    
    def analyze_resource_file(self, file_path: str, content: str, 
                             config: AnalysisConfiguration) -> FileAnalysisResult:
        """
        Analyze a resource file for encoding and cloud service issues.
        
        Args:
            file_path: Path to the resource file
            content: File content
            config: Analysis configuration
            
        Returns:
            FileAnalysisResult with findings
        """
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=FileType.RESOURCE_FILE,
            content_size=len(content)
        )
        
        try:
            file_name = Path(file_path).name.lower()
            
            # Special handling for strings.xml
            if file_name == 'strings.xml':
                return self._analyze_strings_xml(file_path, content, config)
            
            # Regular resource file analysis
            if config.analyze_resource_files:
                # Encoding analysis
                encoding_findings = self.encoding_analyzer.analyze_content(
                    content, f"resource:{Path(file_path).name}", FileType.RESOURCE_FILE
                )
                result.encoding_findings.extend(encoding_findings)
                
                # Cloud service analysis
                cloud_findings = self.cloud_analyzer.analyze_cloud_services(
                    content, f"resource:{Path(file_path).name}", FileType.RESOURCE_FILE
                )
                result.cloud_findings.extend(cloud_findings)
            
            # XML-specific analysis
            if file_path.endswith('.xml'):
                self._analyze_xml_content(content, result)
            
            # JSON-specific analysis
            elif file_path.endswith('.json'):
                self._analyze_json_content(content, result)
            
        except Exception as e:
            result.analysis_successful = False
            result.error_message = f"Error analyzing resource file: {e}"
            logger.error(f"Error analyzing resource file {file_path}: {e}")
        
        return result
    
    def _analyze_strings_xml(self, file_path: str, content: str, 
                            config: AnalysisConfiguration) -> FileAnalysisResult:
        """Specialized analysis for strings.xml files."""
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=FileType.STRINGS_XML,
            content_size=len(content)
        )
        
        try:
            # Parse XML content
            root = ET.fromstring(content)
            
            # Analyze each string entry
            for string_elem in root.findall('.//string'):
                string_name = string_elem.get('name', '')
                string_value = string_elem.text or ''
                
                if string_value:
                    # Encoding analysis on string values
                    encoding_findings = self.encoding_analyzer.analyze_content(
                        string_value, f"strings.xml:{string_name}", FileType.STRINGS_XML
                    )
                    result.encoding_findings.extend(encoding_findings)
                    
                    # Cloud service analysis on string values
                    cloud_findings = self.cloud_analyzer.analyze_cloud_services(
                        string_value, f"strings.xml:{string_name}", FileType.STRINGS_XML
                    )
                    result.cloud_findings.extend(cloud_findings)
        
        except ET.ParseError as e:
            # If XML parsing fails, fall back to text analysis
            logger.debug(f"XML parsing failed for {file_path}, using text analysis: {e}")
            encoding_findings = self.encoding_analyzer.analyze_content(
                content, f"strings.xml", FileType.STRINGS_XML
            )
            result.encoding_findings.extend(encoding_findings)
            
            cloud_findings = self.cloud_analyzer.analyze_cloud_services(
                content, f"strings.xml", FileType.STRINGS_XML
            )
            result.cloud_findings.extend(cloud_findings)
        
        except Exception as e:
            result.analysis_successful = False
            result.error_message = f"Error analyzing strings.xml: {e}"
            logger.error(f"Error analyzing strings.xml {file_path}: {e}")
        
        return result
    
    def _analyze_xml_content(self, content: str, result: FileAnalysisResult):
        """Analyze XML-specific patterns and structures."""
        # Check for Android manifest patterns
        if 'android:' in content:
            # Analyze Android XML configurations
            self._analyze_android_xml_patterns(content, result)
        
        # Check for configuration vulnerabilities
        if 'android:allowBackup="true"' in content:
            # Create finding for backup vulnerability
            result.vulnerabilities.append({
                'type': 'backup_vulnerability',
                'description': 'Application allows backup which may expose sensitive data',
                'severity': 'medium',
                'pattern': 'android:allowBackup="true"'
            })
    
    def _analyze_android_xml_patterns(self, content: str, result: FileAnalysisResult):
        """Analyze Android XML patterns for potential security issues."""
        # Check for common Android security patterns
        android_patterns = [
            ('android:exported="true"', 'exported_component', 'Component exported without proper protection'),
            ('android:debuggable="true"', 'debug_enabled', 'Debug mode enabled in production'),
            ('android:allowBackup="true"', 'backup_enabled', 'Backup allowed without encryption'),
            ('android:usesCleartextTraffic="true"', 'cleartext_traffic', 'Cleartext traffic allowed'),
            ('android:networkSecurityConfig', 'network_security_config', 'Network security configuration found')
        ]
        
        for pattern, vuln_type, description in android_patterns:
            if pattern in content:
                result.vulnerabilities.append({
                    'type': vuln_type,
                    'description': description,
                    'severity': 'high' if 'debug' in pattern or 'exported' in pattern else 'medium',
                    'pattern': pattern
                })
    
    def _analyze_json_content(self, content: str, result: FileAnalysisResult):
        """Analyze JSON-specific patterns and structures."""
        try:
            import json
            data = json.loads(content)
            
            # Analyze JSON structure for sensitive data
            self._scan_json_recursively(data, result)
            
        except json.JSONDecodeError:
            # If JSON parsing fails, analyze as text
            result.errors.append("Invalid JSON format, analyzing as text")
            self._analyze_text_patterns(content, result)
    
    def _scan_json_recursively(self, data, result: FileAnalysisResult, path: str = ""):
        """Recursively scan JSON data for sensitive patterns."""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check for sensitive keys
                if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'token', 'password']):
                    # Create finding for potential credential
                    result.vulnerabilities.append({
                        'type': 'sensitive_data_exposure',
                        'description': f'Potential credential found in JSON: {key}',
                        'severity': 'high',
                        'pattern': f'{current_path}{key}',
                        'value': str(value)[:100] + '...' if len(str(value)) > 100 else str(value)
                    })
                
                self._scan_json_recursively(value, result, current_path)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                self._scan_json_recursively(item, result, current_path)

class ConfigFileAnalyzer:
    """Specialized analyzer for configuration files."""
    
    def __init__(self, encoding_analyzer: AdvancedEncodingAnalyzer, 
                 cloud_analyzer: CloudServiceAnalyzer):
        self.encoding_analyzer = encoding_analyzer
        self.cloud_analyzer = cloud_analyzer
    
    def analyze_config_file(self, file_path: str, content: str, 
                           config: AnalysisConfiguration) -> FileAnalysisResult:
        """
        Analyze a configuration file for encoding and cloud service issues.
        
        Args:
            file_path: Path to the config file
            content: File content
            config: Analysis configuration
            
        Returns:
            FileAnalysisResult with findings
        """
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=FileType.CONFIG_FILE,
            content_size=len(content)
        )
        
        try:
            if config.analyze_config_files:
                # Encoding analysis
                encoding_findings = self.encoding_analyzer.analyze_content(
                    content, f"config:{Path(file_path).name}", FileType.CONFIG_FILE
                )
                result.encoding_findings.extend(encoding_findings)
                
                # Cloud service analysis
                cloud_findings = self.cloud_analyzer.analyze_cloud_services(
                    content, f"config:{Path(file_path).name}", FileType.CONFIG_FILE
                )
                result.cloud_findings.extend(cloud_findings)
            
            # Configuration-specific analysis
            self._analyze_config_patterns(content, result)
            
        except Exception as e:
            result.analysis_successful = False
            result.error_message = f"Error analyzing config file: {e}"
            logger.error(f"Error analyzing config file {file_path}: {e}")
        
        return result
    
    def _analyze_config_patterns(self, content: str, result: FileAnalysisResult):
        """Analyze configuration-specific security patterns."""
        # Check for debug configurations
        if 'debug=true' in content.lower() or 'debug: true' in content.lower():
            # Create finding for debug mode
            result.vulnerabilities.append({
                'type': 'debug_mode_enabled',
                'description': 'Debug mode enabled in configuration',
                'severity': 'high',
                'pattern': 'debug=true or debug: true'
            })
        
        # Check for insecure SSL configurations
        if 'ssl_verify=false' in content.lower() or 'verify_ssl: false' in content.lower():
            # Create finding for SSL verification disabled
            result.vulnerabilities.append({
                'type': 'ssl_verification_disabled',
                'description': 'SSL certificate verification disabled',
                'severity': 'high',
                'pattern': 'ssl_verify=false or verify_ssl: false'
            })

class NativeFileAnalyzer:
    """Specialized analyzer for native binary files."""
    
    def __init__(self, encoding_analyzer: AdvancedEncodingAnalyzer, 
                 cloud_analyzer: CloudServiceAnalyzer):
        self.encoding_analyzer = encoding_analyzer
        self.cloud_analyzer = cloud_analyzer
    
    def analyze_native_file(self, file_path: str, content: Optional[str], 
                           config: AnalysisConfiguration) -> FileAnalysisResult:
        """
        Analyze a native binary file for encoding and cloud service issues.
        
        Args:
            file_path: Path to the native file
            content: Extracted string content (if available)
            config: Analysis configuration
            
        Returns:
            FileAnalysisResult with findings
        """
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=FileType.NATIVE_FILE,
            content_size=len(content) if content else 0
        )
        
        try:
            if config.analyze_native_files:
                # Extract strings from binary if content not provided
                if not content and config.extract_strings_from_binaries:
                    content = self._extract_strings_from_binary(file_path)
                
                if content:
                    # Encoding analysis on extracted strings
                    encoding_findings = self.encoding_analyzer.analyze_content(
                        content, f"native:{Path(file_path).name}", FileType.NATIVE_FILE
                    )
                    result.encoding_findings.extend(encoding_findings)
                    
                    # Cloud service analysis on extracted strings
                    cloud_findings = self.cloud_analyzer.analyze_cloud_services(
                        content, f"native:{Path(file_path).name}", FileType.NATIVE_FILE
                    )
                    result.cloud_findings.extend(cloud_findings)
            
        except Exception as e:
            result.analysis_successful = False
            result.error_message = f"Error analyzing native file: {e}"
            logger.error(f"Error analyzing native file {file_path}: {e}")
        
        return result
    
    def _extract_strings_from_binary(self, file_path: str) -> str:
        """Extract printable strings from binary file."""
        try:
            # Use strings command if available
            result = subprocess.run(
                ['strings', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return result.stdout
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        # Fallback: manual string extraction
        try:
            with open(file_path, 'rb') as f:
                binary_content = f.read()
            
            # Extract ASCII strings (length >= 4)
            strings = []
            current_string = ""
            
            for byte in binary_content:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""
            
            # Add final string if valid
            if len(current_string) >= 4:
                strings.append(current_string)
            
            return '\n'.join(strings)
            
        except Exception as e:
            logger.debug(f"Error extracting strings from {file_path}: {e}")
            return ""

class FileAnalysisOrchestrator:
    """Orchestrates analysis across different file types."""
    
    def __init__(self, encoding_analyzer: AdvancedEncodingAnalyzer, 
                 cloud_analyzer: CloudServiceAnalyzer):
        self.encoding_analyzer = encoding_analyzer
        self.cloud_analyzer = cloud_analyzer
        
        # Initialize specialized analyzers
        self.source_analyzer = SourceCodeAnalyzer(encoding_analyzer, cloud_analyzer)
        self.resource_analyzer = ResourceFileAnalyzer(encoding_analyzer, cloud_analyzer)
        self.config_analyzer = ConfigFileAnalyzer(encoding_analyzer, cloud_analyzer)
        self.native_analyzer = NativeFileAnalyzer(encoding_analyzer, cloud_analyzer)
        
        self.file_type_detector = FileTypeDetector()
    
    def analyze_files(self, file_paths: List[str], 
                     config: AnalysisConfiguration) -> List[FileAnalysisResult]:
        """
        Analyze multiple files based on their types.
        
        Args:
            file_paths: List of file paths to analyze
            config: Analysis configuration
            
        Returns:
            List of FileAnalysisResult objects
        """
        results = []
        
        for file_path in file_paths:
            try:
                # Skip files that are too large
                if self._is_file_too_large(file_path, config.max_file_size_mb):
                    logger.debug(f"Skipping large file: {file_path}")
                    continue
                
                # Detect file type
                file_type = self.file_type_detector.detect_file_type(file_path)
                
                # Skip binary files if not configured to analyze them
                if (file_type == FileType.BINARY and not config.analyze_binary_files):
                    continue
                
                # Analyze based on file type
                result = self._analyze_single_file(file_path, file_type, config)
                if result:
                    results.append(result)
                    
            except Exception as e:
                logger.error(f"Error analyzing file {file_path}: {e}")
                # Create error result
                error_result = FileAnalysisResult(
                    file_path=file_path,
                    file_type=FileType.OTHER,
                    analysis_successful=False,
                    error_message=str(e)
                )
                results.append(error_result)
        
        return results
    
    def _analyze_single_file(self, file_path: str, file_type: FileType, 
                            config: AnalysisConfiguration) -> Optional[FileAnalysisResult]:
        """Analyze a single file based on its type."""
        try:
            # Read file content
            content = None
            if file_type != FileType.NATIVE_FILE or config.extract_strings_from_binaries:
                content = self._read_file_content(file_path, file_type)
            
            # Route to appropriate analyzer
            if file_type == FileType.SOURCE_CODE:
                return self.source_analyzer.analyze_source_file(file_path, content, config)
            
            elif file_type in [FileType.RESOURCE_FILE, FileType.STRINGS_XML]:
                return self.resource_analyzer.analyze_resource_file(file_path, content, config)
            
            elif file_type == FileType.CONFIG_FILE:
                return self.config_analyzer.analyze_config_file(file_path, content, config)
            
            elif file_type == FileType.NATIVE_FILE:
                return self.native_analyzer.analyze_native_file(file_path, content, config)
            
            else:
                # Generic analysis for other file types
                result = FileAnalysisResult(
                    file_path=file_path,
                    file_type=file_type,
                    content_size=len(content) if content else 0
                )
                
                if content:
                    # Basic encoding and cloud analysis
                    encoding_findings = self.encoding_analyzer.analyze_content(
                        content, f"other:{Path(file_path).name}", file_type
                    )
                    result.encoding_findings.extend(encoding_findings)
                    
                    cloud_findings = self.cloud_analyzer.analyze_cloud_services(
                        content, f"other:{Path(file_path).name}", file_type
                    )
                    result.cloud_findings.extend(cloud_findings)
                
                return result
        
        except Exception as e:
            logger.error(f"Error in single file analysis {file_path}: {e}")
            return None
    
    def _read_file_content(self, file_path: str, file_type: FileType) -> Optional[str]:
        """Read file content safely."""
        try:
            # Check if file is binary
            if self.file_type_detector.is_binary_file(file_path):
                if file_type == FileType.NATIVE_FILE:
                    # Extract strings from binary
                    return self.native_analyzer._extract_strings_from_binary(file_path)
                else:
                    return None
            
            # Read text file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
                
        except Exception as e:
            logger.debug(f"Error reading file {file_path}: {e}")
            return None
    
    def _is_file_too_large(self, file_path: str, max_size_mb: int) -> bool:
        """Check if file is too large for analysis."""
        try:
            file_size = os.path.getsize(file_path)
            max_size_bytes = max_size_mb * 1024 * 1024
            return file_size > max_size_bytes
        except Exception:
            return False
    
    def get_supported_file_types(self) -> List[FileType]:
        """Get list of supported file types for analysis."""
        return [
            FileType.SOURCE_CODE,
            FileType.RESOURCE_FILE,
            FileType.CONFIG_FILE,
            FileType.NATIVE_FILE,
            FileType.STRINGS_XML,
            FileType.MANIFEST
        ]
    
    def get_analysis_statistics(self) -> Dict[str, int]:
        """Get analysis statistics from all analyzers."""
        stats = {}
        stats.update(self.encoding_analyzer.get_analysis_statistics())
        stats.update(self.cloud_analyzer.get_analysis_statistics())
        return stats 