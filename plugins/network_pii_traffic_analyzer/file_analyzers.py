"""
File Analyzers for Network PII Traffic Analysis.

This module provides specialized analyzers for different file types to detect
PII in various contexts including source code, resources, manifests, and configurations.
"""

import os
import re
import json
import logging
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union
import xml.etree.ElementTree as ET

from .data_structures import (
    FileAnalysisResult, PIINetworkFinding, NetworkEndpoint,
    PIIType, SeverityLevel, TransmissionMethod, FileType,
    PIIAnalysisConfiguration, AnalysisError, PIIPattern
)
from .network_pii_analyzer import NetworkPIIAnalyzer
from .confidence_calculator import ConfidenceEvidence

logger = logging.getLogger(__name__)

class SourceFileAnalyzer:
    """Analyzer for source code files (Java, Kotlin, Dart, etc.)."""
    
    def __init__(self, pattern_library: Any, confidence_calculator: Any):
        """Initialize the source file analyzer."""
        self.pattern_library = pattern_library
        self.confidence_calculator = confidence_calculator
        self.pii_analyzer = NetworkPIIAnalyzer(
            pattern_library=pattern_library,
            confidence_calculator=confidence_calculator
        )
        
        # Source file extensions
        self.source_extensions = {'.java', '.kt', '.dart', '.scala', '.groovy'}
        
        # Network call patterns
        self.network_patterns = [
            r'new\s+URL\s*\(\s*["\']([^"\']+)["\']',  # new URL("...")
            r'HttpURLConnection\s*[^;]*["\']([^"\']+)["\']',  # HttpURLConnection
            r'OkHttpClient\s*[^;]*["\']([^"\']+)["\']',  # OkHttp
            r'Retrofit\s*[^;]*["\']([^"\']+)["\']',  # Retrofit
            r'Volley\s*[^;]*["\']([^"\']+)["\']',  # Volley
            r'okhttp3\.[^;]*["\']([^"\']+)["\']',  # OkHttp3
            r'http[s]?://[^\s\'"]*',  # Direct URLs
        ]
        
        logger.info("Source file analyzer initialized with professional confidence system")

    def _calculate_confidence(self, pattern_id: str, evidence: ConfidenceEvidence, 
                            fallback_confidence: float = 0.7) -> float:
        """
        Calculate confidence using the professional confidence calculator if available.
        
        Args:
            pattern_id: Pattern identifier for confidence calculation
            evidence: Evidence for confidence calculation
            fallback_confidence: Fallback confidence if calculator unavailable
            
        Returns:
            float: confidence score
        """
        if self.confidence_calculator:
            try:
                # Create a dummy pattern for confidence calculation
                dummy_pattern = PIIPattern(
                    pattern_id=pattern_id,
                    name=pattern_id.replace('_', ' ').title(),
                    pattern='',
                    pii_type=evidence.additional_context.get('pii_type', PIIType.UNKNOWN)
                )
                return self.confidence_calculator.calculate_confidence(dummy_pattern, evidence)
            except Exception as e:
                logger.warning(f"Confidence calculation failed for {pattern_id}, using fallback: {e}")
                return fallback_confidence
        else:
            logger.debug("No confidence calculator available, using fallback")
            return fallback_confidence

    def is_source_file(self, file_path: str) -> bool:
        """Check if file is a source code file."""
        return Path(file_path).suffix.lower() in self.source_extensions

    def analyze_source_file(self, file_path: str, content: str) -> FileAnalysisResult:
        """Analyze source code file for PII patterns."""
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=FileType.SOURCE_CODE,
            content_size=len(content),
            lines_analyzed=content.count('\n') + 1
        )
        
        try:
            # Use main PII analyzer for pattern detection
            result = self.pii_analyzer.analyze_content(content, file_path, FileType.SOURCE_CODE)
            
            # Additional source-specific analysis
            self._analyze_network_calls(content, file_path, result)
            self._analyze_intent_creation(content, file_path, result)
            self._analyze_shared_preferences(content, file_path, result)
            self._analyze_database_operations(content, file_path, result)
            
        except Exception as e:
            logger.error(f"Error analyzing source file {file_path}: {e}")
            result.analysis_successful = False
            result.error_message = str(e)
        
        return result

    def analyze_source_files(self, context: Any) -> List[FileAnalysisResult]:
        """Analyze source files in context."""
        results = []
        # Mock implementation - in real scenario would scan actual files
        logger.info("Analyzing source files...")
        return results

    def _analyze_network_calls(self, content: str, file_path: str, 
                               result: FileAnalysisResult) -> None:
        """Analyze network calls in source code for PII transmission."""
        for pattern in self.network_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.groups():
                    url = match.group(1) if match.groups() else match.group(0)
                    self._analyze_network_call_context(match, content, file_path, result)
                
                # Create network endpoint
                endpoint = NetworkEndpoint(
                    url=url,
                    method="Unknown",
                    protocol="HTTPS" if url.startswith('https') else "HTTP",
                    uses_tls=url.startswith('https')
                )
                result.network_endpoints.append(endpoint)

    def _analyze_network_call_context(self, match: re.Match, content: str,
                                      file_path: str, result: FileAnalysisResult) -> None:
        """Analyze context around network calls for PII."""
        # Extract context around the match
        start = max(0, match.start() - 200)
        end = min(len(content), match.end() + 200)
        context = content[start:end]
        
        # Look for variable assignments that might contain PII
        var_patterns = [
            r'(\w+)\s*=\s*["\']([^"\']+)["\']',  # var = "value"
            r'put\s*\(\s*["\']([^"\']+)["\']\s*,\s*([^)]+)\)',  # put("key", value)
            r'add\s*\(\s*["\']([^"\']+)["\']\s*,\s*([^)]+)\)',  # add("key", value)
        ]
        
        for var_pattern in var_patterns:
            for var_match in re.finditer(var_pattern, context, re.IGNORECASE):
                key = var_match.group(1)
                value = var_match.group(2) if var_match.groups() and len(var_match.groups()) > 1 else ""
                
                if self._is_pii_related_key(key):
                    self._create_network_context_finding(key, value, file_path, 
                                                       match.start(), result)

    def _analyze_intent_creation(self, content: str, file_path: str,
                                 result: FileAnalysisResult) -> None:
        """Analyze Intent creation for PII data exposure."""
        intent_patterns = [
            r'new\s+Intent\s*\([^)]*\)',  # new Intent(...)
            r'putExtra\s*\(\s*["\']([^"\']+)["\']\s*,\s*([^)]+)\)',  # putExtra("key", value)
            r'setData\s*\(\s*Uri\.parse\s*\(\s*["\']([^"\']+)["\']',  # setData(Uri.parse("..."))
        ]
        
        for pattern in intent_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if 'putExtra' in match.group(0):
                    key = match.group(1)
                    value = match.group(2) if len(match.groups()) > 1 else ""
                    
                    if self._is_pii_related_key(key):
                        self._create_intent_finding(key, value, file_path, match.start(), result)
                
                elif 'setData' in match.group(0) and match.groups():
                    uri = match.group(1)
                    if self._contains_pii_in_uri(uri):
                        self._create_uri_finding(uri, file_path, match.start(), result)

    def _analyze_shared_preferences(self, content: str, file_path: str,
                                    result: FileAnalysisResult) -> None:
        """Analyze SharedPreferences usage for PII storage."""
        pref_patterns = [
            r'putString\s*\(\s*["\']([^"\']+)["\']\s*,\s*([^)]+)\)',  # putString("key", value)
            r'getString\s*\(\s*["\']([^"\']+)["\']',  # getString("key")
            r'editor\.put\w+\s*\(\s*["\']([^"\']+)["\']\s*,\s*([^)]+)\)',  # editor.put*("key", value)
        ]
        
        for pattern in pref_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                key = match.group(1)
                value = match.group(2) if len(match.groups()) > 1 else ""
                
                if self._is_pii_related_key(key):
                    self._create_storage_finding(key, value, file_path, match.start(), result)

    def _analyze_database_operations(self, content: str, file_path: str,
                                     result: FileAnalysisResult) -> None:
        """Analyze database operations for PII storage."""
        db_patterns = [
            r'ContentValues\s*[^;]*put\s*\(\s*["\']([^"\']+)["\']\s*,\s*([^)]+)\)',
            r'execSQL\s*\(\s*["\']([^"\']+)["\']',  # execSQL("...")
            r'rawQuery\s*\(\s*["\']([^"\']+)["\']',  # rawQuery("...")
            r'insert\s*\([^)]*["\']([^"\']+)["\']',  # insert(..., "value")
        ]
        
        for pattern in db_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if 'put' in match.group(0):
                    key = match.group(1)
                    value = match.group(2) if len(match.groups()) > 1 else ""
                    
                    if self._is_pii_related_key(key):
                        self._create_database_finding(key, value, file_path, match.start(), result)

    def _is_pii_related_key(self, key: str) -> bool:
        """Check if a key name suggests PII data."""
        key_lower = key.lower()
        pii_indicators = [
            'android_id', 'device_id', 'imei', 'advertising_id', 'adid',
            'latitude', 'longitude', 'location', 'gps', 'coordinates',
            'email', 'phone', 'name', 'address', 'ssn', 'social',
            'api_key', 'token', 'password', 'secret', 'auth',
            'user_id', 'username', 'userid', 'profile', 'personal'
        ]
        
        return any(indicator in key_lower for indicator in pii_indicators)

    def _contains_pii_in_uri(self, uri: str) -> bool:
        """Check if URI contains PII data."""
        uri_lower = uri.lower()
        pii_patterns = [
            r'android_id=',
            r'device_id=',
            r'imei=',
            r'lat=|latitude=',
            r'lng=|longitude=',
            r'email=',
            r'phone='
        ]
        
        return any(re.search(pattern, uri_lower) for pattern in pii_patterns)

    def _create_network_context_finding(self, key: str, value: str, file_path: str,
                                        position: int, result: FileAnalysisResult) -> None:
        """Create finding for PII in network context."""
        pii_type = self._determine_pii_type_from_key(key)
        
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"{key}={value}"],
            context_factors=["network_context"],
            validation_checks={"pii_type_detected": pii_type != PIIType.UNKNOWN},
            risk_factors=["network_transmission"],
            data_sensitivity=["medium"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"network_context_{hash(f'{key}_{value}_{position}') % 10000:04d}",
            pii_type=pii_type,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.MEDIUM,
            confidence=self._calculate_confidence("network_context", evidence, 0.6),
            description=f"PII '{key}' detected in network call context",
            location=file_path,
            evidence=f"{key}: {value}",
            pattern_matched="network_context",
            matched_value=value,
            attack_vectors=["Network data exposure", "Man-in-the-middle attack"],
            privacy_impact="Medium - PII in network transmission context",
            remediation="Encrypt sensitive data before network transmission",
            masvs_control="MASVS-NETWORK-1",
            mstg_reference="MSTG-NETWORK-1"
        )
        
        result.pii_findings.append(finding)

    def _create_intent_finding(self, key: str, value: str, file_path: str,
                               position: int, result: FileAnalysisResult) -> None:
        """Create finding for PII in Intent."""
        pii_type = self._determine_pii_type_from_key(key)
        
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"putExtra({key}, {value})"],
            context_factors=["intent_extra"],
            validation_checks={"pii_type_detected": pii_type != PIIType.UNKNOWN},
            risk_factors=["intent_interception", "component_hijacking"],
            data_sensitivity=["medium"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"intent_pii_{hash(f'{key}_{value}_{position}') % 10000:04d}",
            pii_type=pii_type,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.MEDIUM,
            confidence=self._calculate_confidence("intent_extra", evidence, 0.7),
            description=f"PII '{key}' detected in Intent extra",
            location=file_path,
            evidence=f"putExtra(\"{key}\", {value})",
            pattern_matched="intent_extra",
            matched_value=value,
            attack_vectors=["Intent interception", "Component hijacking"],
            privacy_impact="Medium - PII exposed through Intent mechanism",
            remediation="Validate Intent recipients and use secure Intent mechanisms",
            masvs_control="MASVS-PLATFORM-1",
            mstg_reference="MSTG-PLATFORM-1"
        )
        
        result.pii_findings.append(finding)

    def _create_uri_finding(self, uri: str, file_path: str, position: int,
                            result: FileAnalysisResult) -> None:
        """Create finding for PII in URI."""
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"URI: {uri}"],
            context_factors=["uri_data"],
            validation_checks={"contains_pii_pattern": self._contains_pii_in_uri(uri)},
            risk_factors=["uri_interception", "data_exposure"],
            data_sensitivity=["medium"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"uri_pii_{hash(f'{uri}_{position}') % 10000:04d}",
            pii_type=PIIType.PERSONAL_IDENTIFIER,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.MEDIUM,
            confidence=self._calculate_confidence("uri_data", evidence, 0.6),
            description="PII detected in URI data",
            location=file_path,
            evidence=f"URI: {uri}",
            pattern_matched="uri_data",
            matched_value=uri,
            attack_vectors=["URI interception", "Data exposure"],
            privacy_impact="Medium - PII in URI parameters",
            remediation="Avoid including PII in URI parameters",
            masvs_control="MASVS-NETWORK-1",
            mstg_reference="MSTG-NETWORK-1"
        )
        
        result.pii_findings.append(finding)

    def _create_storage_finding(self, key: str, value: str, file_path: str,
                                position: int, result: FileAnalysisResult) -> None:
        """Create finding for PII in storage."""
        pii_type = self._determine_pii_type_from_key(key)
        
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"putString({key}, {value})"],
            context_factors=["shared_preferences"],
            validation_checks={"pii_type_detected": pii_type != PIIType.UNKNOWN},
            risk_factors=["local_storage_exposure"],
            data_sensitivity=["low"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"storage_pii_{hash(f'{key}_{value}_{position}') % 10000:04d}",
            pii_type=pii_type,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.LOW,
            confidence=self._calculate_confidence("shared_preferences", evidence, 0.5),
            description=f"PII '{key}' detected in SharedPreferences",
            location=file_path,
            evidence=f"putString(\"{key}\", {value})",
            pattern_matched="shared_preferences",
            matched_value=value,
            attack_vectors=["Local storage access", "Data extraction"],
            privacy_impact="Low - PII in local storage",
            remediation="Encrypt sensitive data in SharedPreferences",
            masvs_control="MASVS-STORAGE-1",
            mstg_reference="MSTG-STORAGE-1"
        )
        
        result.pii_findings.append(finding)

    def _create_database_finding(self, key: str, value: str, file_path: str,
                                 position: int, result: FileAnalysisResult) -> None:
        """Create finding for PII in database operations."""
        pii_type = self._determine_pii_type_from_key(key)
        
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"Database operation: {key}={value}"],
            context_factors=["database_operation"],
            validation_checks={"pii_type_detected": pii_type != PIIType.UNKNOWN},
            risk_factors=["database_access", "sql_injection", "data_extraction"],
            data_sensitivity=["medium"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"database_pii_{hash(f'{key}_{value}_{position}') % 10000:04d}",
            pii_type=pii_type,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.MEDIUM,
            confidence=self._calculate_confidence("database_operation", evidence, 0.6),
            description=f"PII '{key}' detected in database operation",
            location=file_path,
            evidence=f"Database operation with {key}: {value}",
            pattern_matched="database_operation",
            matched_value=value,
            attack_vectors=["Database access", "SQL injection", "Data extraction"],
            privacy_impact="Medium - PII in database storage",
            remediation="Encrypt sensitive data in database and use parameterized queries",
            masvs_control="MASVS-STORAGE-1",
            mstg_reference="MSTG-STORAGE-1"
        )
        
        result.pii_findings.append(finding)

    def _determine_pii_type_from_key(self, key: str) -> PIIType:
        """Determine PII type from key name."""
        key_lower = key.lower()
        
        if any(term in key_lower for term in ['android_id', 'device_id', 'imei', 'advertising_id']):
            return PIIType.DEVICE_IDENTIFIER
        elif any(term in key_lower for term in ['lat', 'latitude', 'lng', 'longitude', 'location', 'gps']):
            return PIIType.LOCATION_DATA
        elif any(term in key_lower for term in ['email', 'phone', 'name', 'address', 'ssn']):
            return PIIType.PERSONAL_IDENTIFIER
        elif any(term in key_lower for term in ['api_key', 'token', 'password', 'secret', 'auth']):
            return PIIType.AUTHENTICATION_DATA
        else:
            return PIIType.UNKNOWN

class ResourceFileAnalyzer:
    """Analyzer for resource files (XML, JSON, YAML, properties)."""
    
    def __init__(self, pattern_library: Any, confidence_calculator: Any):
        """Initialize the resource file analyzer."""
        self.pattern_library = pattern_library
        self.confidence_calculator = confidence_calculator
        self.pii_analyzer = NetworkPIIAnalyzer(
            pattern_library=pattern_library,
            confidence_calculator=confidence_calculator
        )
        
        # Resource file extensions
        self.resource_extensions = {
            '.xml', '.json', '.yaml', '.yml', '.properties', 
            '.config', '.conf', '.ini', '.plist'
        }
        
        logger.info("Resource file analyzer initialized")

    def is_resource_file(self, file_path: str) -> bool:
        """Check if file is a resource file."""
        return Path(file_path).suffix.lower() in self.resource_extensions

    def analyze_resource_file(self, file_path: str, content: str) -> FileAnalysisResult:
        """Analyze resource file for PII patterns."""
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=FileType.RESOURCE_FILE,
            content_size=len(content),
            lines_analyzed=content.count('\n') + 1
        )
        
        try:
            # Use main PII analyzer for pattern detection
            result = self.pii_analyzer.analyze_content(content, file_path, FileType.RESOURCE_FILE)
            
            # Additional resource-specific analysis
            if file_path.endswith('.xml'):
                self._analyze_xml_resources(content, file_path, result)
            elif file_path.endswith('.json'):
                self._analyze_json_resources(content, file_path, result)
            elif file_path.endswith(('.yaml', '.yml')):
                self._analyze_yaml_resources(content, file_path, result)
            elif file_path.endswith('.properties'):
                self._analyze_properties_resources(content, file_path, result)
            
        except Exception as e:
            logger.error(f"Error analyzing resource file {file_path}: {e}")
            result.analysis_successful = False
            result.error_message = str(e)
        
        return result

    def analyze_resource_files(self, context: Any) -> List[FileAnalysisResult]:
        """Analyze resource files in context."""
        results = []
        # Mock implementation - in real scenario would scan actual files
        logger.info("Analyzing resource files...")
        return results

    def _analyze_xml_resources(self, content: str, file_path: str,
                               result: FileAnalysisResult) -> None:
        """Analyze XML resource files for PII."""
        try:
            root = ET.fromstring(content)
            
            # Check for network security config
            if 'network_security_config' in file_path or root.tag == 'network-security-config':
                self._analyze_network_security_config(root, file_path, result)
            
            # Analyze string resources
            for string_elem in root.findall('.//string'):
                name = string_elem.get('name', '')
                value = string_elem.text or ''
                
                if self._is_pii_related_resource(name, value):
                    self._create_resource_finding('xml_string', name, value, file_path, result)
            
            # Analyze other XML elements
            for elem in root.iter():
                if elem.text and self._is_pii_related_resource(elem.tag, elem.text):
                    self._create_resource_finding('xml_element', elem.tag, elem.text, file_path, result)
                
                # Check attributes
                for attr_name, attr_value in elem.attrib.items():
                    if self._is_pii_related_resource(attr_name, attr_value):
                        self._create_resource_finding('xml_attribute', attr_name, attr_value, file_path, result)
        
        except ET.ParseError as e:
            logger.debug(f"Could not parse XML file {file_path}: {e}")

    def _analyze_json_resources(self, content: str, file_path: str,
                                result: FileAnalysisResult) -> None:
        """Analyze JSON resource files for PII."""
        try:
            data = json.loads(content)
            self._traverse_json_for_pii(data, file_path, result)
        except json.JSONDecodeError as e:
            logger.debug(f"Could not parse JSON file {file_path}: {e}")

    def _analyze_yaml_resources(self, content: str, file_path: str,
                                result: FileAnalysisResult) -> None:
        """Analyze YAML resource files for PII."""
        try:
            # Try to parse as YAML (if yaml library is available)
            import yaml
            data = yaml.safe_load(content)
            self._traverse_json_for_pii(data, file_path, result)  # Same structure traversal
        except (ImportError, Exception) as e:
            logger.debug(f"Could not parse YAML file {file_path}: {e}")
            # Fallback to text-based analysis
            self._analyze_properties_resources(content, file_path, result)

    def _analyze_properties_resources(self, content: str, file_path: str,
                                      result: FileAnalysisResult) -> None:
        """Analyze properties/configuration files for PII."""
        # Look for key-value pairs
        prop_patterns = [
            r'^([^#\n]*?)[:=]\s*(.+)$',  # key=value or key: value
            r'^(\w+)\s+(.+)$',  # key value (space separated)
        ]
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            for pattern in prop_patterns:
                match = re.match(pattern, line)
                if match:
                    key = match.group(1).strip()
                    value = match.group(2).strip()
                    
                    if self._is_pii_related_resource(key, value):
                        self._create_resource_finding('properties', key, value, file_path, result)
                    break

    def _analyze_network_security_config(self, root: ET.Element, file_path: str,
                                         result: FileAnalysisResult) -> None:
        """Analyze network security configuration for security issues."""
        # Check for cleartext traffic permissions
        for domain_config in root.findall('.//domain-config'):
            cleartext_permitted = domain_config.get('cleartextTrafficPermitted', 'false')
            if cleartext_permitted.lower() == 'true':
                self._create_network_config_finding('cleartext_traffic_permitted', file_path, result)
        
        # Check for certificate pinning
        has_pinning = root.findall('.//pin-set')
        if not has_pinning:
            self._create_network_config_finding('no_certificate_pinning', file_path, result)

    def _traverse_json_for_pii(self, data: Any, file_path: str, 
                               result: FileAnalysisResult, path: str = "") -> None:
        """Recursively traverse JSON data for PII."""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                if isinstance(value, str) and self._is_pii_related_resource(key, value):
                    self._create_resource_finding('json', key, value, f"{file_path}:{current_path}", result)
                elif isinstance(value, (dict, list)):
                    self._traverse_json_for_pii(value, file_path, result, current_path)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                if isinstance(item, (dict, list, str)):
                    self._traverse_json_for_pii(item, file_path, result, current_path)

    def _is_pii_related_resource(self, key: str, value: str) -> bool:
        """Check if a resource key-value pair contains PII."""
        key_lower = key.lower()
        value_lower = value.lower() if isinstance(value, str) else ""
        
        # PII-related key names
        pii_key_indicators = [
            'api_key', 'apikey', 'key', 'token', 'secret', 'password',
            'email', 'mail', 'phone', 'tel', 'mobile',
            'android_id', 'device_id', 'imei', 'advertising_id',
            'latitude', 'longitude', 'location', 'gps', 'coordinates',
            'address', 'street', 'city', 'postal', 'zip',
            'name', 'username', 'user_id', 'userid',
            'ssn', 'social', 'license', 'passport'
        ]
        
        # Check key indicators
        key_has_pii = any(indicator in key_lower for indicator in pii_key_indicators)
        
        # PII patterns in values
        pii_value_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone number
            r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',  # UUID
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP address
            r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',  # MAC address
        ]
        
        value_has_pii = any(re.search(pattern, value_lower) for pattern in pii_value_patterns)
        
        return key_has_pii or value_has_pii

    def _create_resource_finding(self, resource_type: str, key: str, value: str,
                                 location: str, result: FileAnalysisResult) -> None:
        """Create finding for PII in resource file."""
        pii_type = self._determine_pii_type_from_resource(key, value)
        
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"{key}: {value}"],
            context_factors=[f"{resource_type}_resource"],
            validation_checks={"pii_type_detected": pii_type != PIIType.UNKNOWN},
            risk_factors=["resource_file_exposure", "configuration_leakage"],
            data_sensitivity=["medium"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"resource_pii_{hash(f'{key}_{value}_{location}') % 10000:04d}",
            pii_type=pii_type,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.MEDIUM,
            confidence=self._calculate_confidence(f"{resource_type}_resource", evidence, 0.6),
            description=f"PII detected in {resource_type} resource '{key}'",
            location=location,
            evidence=f"{key}: {value}",
            pattern_matched=f"{resource_type}_resource",
            matched_value=value,
            attack_vectors=["Resource file exposure", "Configuration leakage"],
            privacy_impact="Medium - PII in resource files",
            remediation="Remove or encrypt PII in resource files",
            masvs_control="MASVS-STORAGE-4",
            mstg_reference="MSTG-STORAGE-4"
        )
        
        result.pii_findings.append(finding)

    def _create_network_config_finding(self, config_type: str, file_path: str,
                                       result: FileAnalysisResult) -> None:
        """Create finding for network security configuration issues."""
        severity = SeverityLevel.HIGH if config_type == 'cleartext_traffic_permitted' else SeverityLevel.MEDIUM
        
        descriptions = {
            'cleartext_traffic_permitted': "Cleartext traffic is permitted in network security config",
            'no_certificate_pinning': "No certificate pinning configured in network security config"
        }
        
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"Network config: {config_type}"],
            context_factors=["network_security_config"],
            validation_checks={"is_security_vulnerability": True},
            risk_factors=["mitm_attack", "traffic_interception", "certificate_bypass"],
            data_sensitivity=["high"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"network_config_{config_type}_{hash(file_path) % 10000:04d}",
            pii_type=PIIType.NETWORK_IDENTIFIER,
            transmission_method=TransmissionMethod.HTTP if config_type == 'cleartext_traffic_permitted' else TransmissionMethod.HTTPS,
            severity=severity,
            confidence=self._calculate_confidence("network_security_config", evidence, 0.9),
            description=descriptions.get(config_type, f"Network security issue: {config_type}"),
            location=file_path,
            evidence=f"Network security configuration: {config_type}",
            pattern_matched="network_security_config",
            attack_vectors=["Man-in-the-middle attack", "Traffic interception", "Certificate bypass"],
            privacy_impact="High - Network security vulnerability",
            remediation="Configure proper network security settings and certificate pinning",
            masvs_control="MASVS-NETWORK-1",
            mstg_reference="MSTG-NETWORK-1"
        )
        
        result.pii_findings.append(finding)

    def _determine_pii_type_from_resource(self, key: str, value: str) -> PIIType:
        """Determine PII type from resource key and value."""
        key_lower = key.lower()
        value_lower = value.lower() if isinstance(value, str) else ""
        
        if any(term in key_lower for term in ['api_key', 'token', 'secret', 'password']):
            return PIIType.AUTHENTICATION_DATA
        elif any(term in key_lower for term in ['email', 'mail']):
            return PIIType.PERSONAL_IDENTIFIER
        elif any(term in key_lower for term in ['phone', 'tel', 'mobile']):
            return PIIType.PERSONAL_IDENTIFIER
        elif any(term in key_lower for term in ['android_id', 'device_id', 'imei']):
            return PIIType.DEVICE_IDENTIFIER
        elif any(term in key_lower for term in ['location', 'gps', 'latitude', 'longitude']):
            return PIIType.LOCATION_DATA
        else:
            return PIIType.UNKNOWN

class ManifestAnalyzer:
    """Analyzer for AndroidManifest.xml files."""
    
    def __init__(self, pattern_library: Any, confidence_calculator: Any):
        """Initialize the manifest analyzer."""
        self.pattern_library = pattern_library
        self.confidence_calculator = confidence_calculator
        self.pii_analyzer = NetworkPIIAnalyzer(
            pattern_library=pattern_library,
            confidence_calculator=confidence_calculator
        )
        logger.info("Manifest analyzer initialized")

    def analyze_manifest(self, context: Any) -> Optional[FileAnalysisResult]:
        """Analyze manifest file in context."""
        # Mock implementation - in real scenario would scan actual manifest
        logger.info("Analyzing manifest file...")
        return None
        
    def analyze_manifest_file(self, file_path: str, content: str) -> FileAnalysisResult:
        """Analyze AndroidManifest.xml for PII-related patterns."""
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=FileType.MANIFEST,
            content_size=len(content),
            lines_analyzed=content.count('\n') + 1
        )
        
        try:
            root = ET.fromstring(content)
            
            # Analyze different aspects of the manifest
            self._analyze_permissions(root, file_path, result)
            self._analyze_intent_filters(root, file_path, result)
            self._analyze_exported_components(root, file_path, result)
            self._analyze_network_config_reference(root, file_path, result)
            
        except ET.ParseError as e:
            logger.error(f"Error parsing manifest {file_path}: {e}")
            result.analysis_successful = False
            result.error_message = f"XML parsing error: {e}"
        except Exception as e:
            logger.error(f"Error analyzing manifest {file_path}: {e}")
            result.analysis_successful = False
            result.error_message = str(e)
        
        return result

    def _analyze_permissions(self, root: ET.Element, file_path: str,
                             result: FileAnalysisResult) -> None:
        """Analyze permissions for PII access capabilities."""
        pii_permissions = {
            'android.permission.READ_PHONE_STATE': PIIType.DEVICE_IDENTIFIER,
            'android.permission.ACCESS_FINE_LOCATION': PIIType.LOCATION_DATA,
            'android.permission.ACCESS_COARSE_LOCATION': PIIType.LOCATION_DATA,
            'android.permission.READ_CONTACTS': PIIType.PERSONAL_IDENTIFIER,
            'android.permission.READ_SMS': PIIType.PERSONAL_IDENTIFIER,
            'android.permission.READ_CALL_LOG': PIIType.PERSONAL_IDENTIFIER,
            'android.permission.GET_ACCOUNTS': PIIType.PERSONAL_IDENTIFIER,
            'android.permission.RECORD_AUDIO': PIIType.BIOMETRIC_DATA,
            'android.permission.CAMERA': PIIType.BIOMETRIC_DATA,
            'android.permission.ACCESS_WIFI_STATE': PIIType.NETWORK_IDENTIFIER,
            'android.permission.BLUETOOTH': PIIType.NETWORK_IDENTIFIER,
        }
        
        for uses_permission in root.findall('.//uses-permission'):
            permission = uses_permission.get('{http://schemas.android.com/apk/res/android}name', '')
            
            if permission in pii_permissions:
                self._create_permission_finding(permission, pii_permissions[permission], file_path, result)

    def _analyze_intent_filters(self, root: ET.Element, file_path: str,
                                result: FileAnalysisResult) -> None:
        """Analyze intent filters for PII exposure risks."""
        for component in root.findall('.//*[intent-filter]'):
            component_name = component.get('{http://schemas.android.com/apk/res/android}name', '')
            
            for intent_filter in component.findall('intent-filter'):
                for data in intent_filter.findall('data'):
                    scheme = data.get('{http://schemas.android.com/apk/res/android}scheme', '')
                    host = data.get('{http://schemas.android.com/apk/res/android}host', '')
                    
                    if scheme or host:
                        self._create_intent_filter_finding(component.tag, scheme, host, file_path, result)

    def _analyze_exported_components(self, root: ET.Element, file_path: str,
                                     result: FileAnalysisResult) -> None:
        """Analyze exported components for potential PII exposure."""
        components = ['activity', 'service', 'receiver', 'provider']
        
        for component_type in components:
            for component in root.findall(f'.//{component_type}'):
                exported = component.get('{http://schemas.android.com/apk/res/android}exported', '')
                name = component.get('{http://schemas.android.com/apk/res/android}name', '')
                
                # Check if explicitly exported or has intent filters (implicit export)
                has_intent_filter = component.find('intent-filter') is not None
                is_exported = exported.lower() == 'true' or (exported == '' and has_intent_filter)
                
                if is_exported:
                    if component_type == 'provider':
                        authorities = component.get('{http://schemas.android.com/apk/res/android}authorities', '')
                        self._create_content_provider_finding(name, authorities, file_path, result)
                    else:
                        self._create_exported_component_finding(component_type, name, file_path, result)

    def _analyze_network_config_reference(self, root: ET.Element, file_path: str,
                                          result: FileAnalysisResult) -> None:
        """Analyze network security config reference."""
        application = root.find('application')
        if application is not None:
            network_config = application.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig', '')
            cleartext_permitted = application.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic', '')
            
            if network_config:
                self._create_network_config_reference_finding(network_config, file_path, result)
            
            if cleartext_permitted.lower() == 'true':
                self._create_cleartext_traffic_finding(file_path, result)

    def _create_permission_finding(self, permission: str, pii_type: PIIType,
                                   file_path: str, result: FileAnalysisResult) -> None:
        """Create finding for PII-related permission."""
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"Permission: {permission}"],
            context_factors=["permission_declaration"],
            validation_checks={"is_pii_permission": pii_type != PIIType.UNKNOWN},
            risk_factors=["permission_abuse", "data_access", "privacy_violation"],
            data_sensitivity=["medium"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"permission_{hash(permission) % 10000:04d}",
            pii_type=pii_type,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.MEDIUM,
            confidence=self._calculate_confidence("permission_declaration", evidence, 0.8),
            description=f"Permission '{permission}' allows access to {pii_type.value.replace('_', ' ')}",
            location=file_path,
            evidence=f"<uses-permission android:name=\"{permission}\" />",
            pattern_matched="permission_declaration",
            matched_value=permission,
            attack_vectors=["Permission abuse", "Data access", "Privacy violation"],
            privacy_impact=f"Medium - Permission allows access to {pii_type.value.replace('_', ' ')}",
            remediation="Ensure permission is necessary and implement proper access controls",
            masvs_control="MASVS-PLATFORM-1",
            mstg_reference="MSTG-PLATFORM-1"
        )
        
        result.pii_findings.append(finding)

    def _create_intent_filter_finding(self, component_type: str, scheme: str,
                                      host: str, file_path: str, result: FileAnalysisResult) -> None:
        """Create finding for intent filter with potential PII exposure."""
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"Intent filter: {scheme}://{host}"],
            context_factors=["intent_filter"],
            validation_checks={"has_data_exposure_risk": True},
            risk_factors=["intent_interception", "url_scheme_abuse"],
            data_sensitivity=["low"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"intent_filter_{hash(f'{scheme}_{host}') % 10000:04d}",
            pii_type=PIIType.NETWORK_IDENTIFIER,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.LOW,
            confidence=self._calculate_confidence("intent_filter", evidence, 0.5),
            description=f"Intent filter in {component_type} may expose data via {scheme}://{host}",
            location=file_path,
            evidence=f"Intent filter: scheme={scheme}, host={host}",
            pattern_matched="intent_filter",
            matched_value=f"{scheme}://{host}",
            attack_vectors=["Intent interception", "URL scheme abuse"],
            privacy_impact="Low - Potential data exposure through intent filters",
            remediation="Validate intent data and restrict component access",
            masvs_control="MASVS-PLATFORM-1",
            mstg_reference="MSTG-PLATFORM-1"
        )
        
        result.pii_findings.append(finding)

    def _create_exported_component_finding(self, component_type: str, name: str,
                                           file_path: str, result: FileAnalysisResult) -> None:
        """Create finding for exported component."""
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"Exported {component_type}: {name}"],
            context_factors=["exported_component"],
            validation_checks={"is_exported": True},
            risk_factors=["external_access", "component_abuse"],
            data_sensitivity=["medium"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"exported_{component_type}_{hash(name) % 10000:04d}",
            pii_type=PIIType.SYSTEM_IDENTIFIER,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.MEDIUM,
            confidence=self._calculate_confidence("exported_component", evidence, 0.6),
            description=f"Exported {component_type} '{name}' may be accessible to other apps",
            location=file_path,
            evidence=f"Exported {component_type}: {name}",
            pattern_matched="exported_component",
            matched_value=name,
            attack_vectors=["Component hijacking", "Intent interception", "Data access"],
            privacy_impact=f"Medium - Exported {component_type} may expose functionality",
            remediation="Review component export necessity and implement proper access controls",
            masvs_control="MASVS-PLATFORM-1",
            mstg_reference="MSTG-PLATFORM-1"
        )
        
        result.pii_findings.append(finding)

    def _create_content_provider_finding(self, name: str, authorities: str,
                                         file_path: str, result: FileAnalysisResult) -> None:
        """Create finding for exported content provider."""
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"Content provider: {name} authorities: {authorities}"],
            context_factors=["content_provider"],
            validation_checks={"is_exported": True, "has_authorities": bool(authorities)},
            risk_factors=["data_exposure", "unauthorized_access", "content_leakage"],
            data_sensitivity=["high"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"content_provider_{hash(f'{name}_{authorities}') % 10000:04d}",
            pii_type=PIIType.PERSONAL_IDENTIFIER,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.HIGH,
            confidence=self._calculate_confidence("content_provider", evidence, 0.8),
            description=f"Exported content provider '{name}' with authorities '{authorities}'",
            location=file_path,
            evidence=f"Content provider: {name}, authorities: {authorities}",
            pattern_matched="content_provider",
            matched_value=f"{name}|{authorities}",
            attack_vectors=["Data access", "SQL injection", "Content provider abuse"],
            privacy_impact="High - Content provider may expose sensitive data",
            remediation="Implement proper access controls and data validation for content provider",
            masvs_control="MASVS-PLATFORM-1",
            mstg_reference="MSTG-PLATFORM-1"
        )
        
        result.pii_findings.append(finding)

    def _create_network_config_reference_finding(self, network_config: str,
                                                 file_path: str, result: FileAnalysisResult) -> None:
        """Create finding for network security config reference."""
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"networkSecurityConfig: {network_config}"],
            context_factors=["network_config_reference"],
            validation_checks={"has_network_config": bool(network_config)},
            risk_factors=[],
            data_sensitivity=["info"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"network_config_ref_{hash(network_config) % 10000:04d}",
            pii_type=PIIType.NETWORK_IDENTIFIER,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.INFO,
            confidence=self._calculate_confidence("network_config_reference", evidence, 0.9),
            description=f"Network security config referenced: {network_config}",
            location=file_path,
            evidence=f"android:networkSecurityConfig=\"{network_config}\"",
            pattern_matched="network_config_reference",
            matched_value=network_config,
            attack_vectors=[],
            privacy_impact="Info - Network security configuration in use",
            remediation="Review network security configuration for proper settings",
            masvs_control="MASVS-NETWORK-1",
            mstg_reference="MSTG-NETWORK-1"
        )
        
        result.pii_findings.append(finding)

    def _create_cleartext_traffic_finding(self, file_path: str, result: FileAnalysisResult) -> None:
        """Create finding for cleartext traffic permission."""
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=["usesCleartextTraffic=true"],
            context_factors=["cleartext_traffic"],
            validation_checks={"allows_cleartext": True},
            risk_factors=["mitm_attack", "traffic_interception", "data_exposure"],
            data_sensitivity=["high"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"cleartext_traffic_{hash(file_path) % 10000:04d}",
            pii_type=PIIType.NETWORK_IDENTIFIER,
            transmission_method=TransmissionMethod.HTTP,
            severity=SeverityLevel.HIGH,
            confidence=self._calculate_confidence("cleartext_traffic", evidence, 0.9),
            description="Application permits cleartext network traffic",
            location=file_path,
            evidence="android:usesCleartextTraffic=\"true\"",
            pattern_matched="cleartext_traffic",
            matched_value="true",
            attack_vectors=["Man-in-the-middle attack", "Traffic interception", "Data exposure"],
            privacy_impact="High - Cleartext traffic allows network eavesdropping",
            remediation="Disable cleartext traffic and use HTTPS for all network communications",
            masvs_control="MASVS-NETWORK-1",
            mstg_reference="MSTG-NETWORK-1"
        )
        
        result.pii_findings.append(finding)

class ConfigurationAnalyzer:
    """Analyzer for configuration files and environment variables."""
    
    def __init__(self, pattern_library: Any, confidence_calculator: Any):
        """Initialize the configuration analyzer."""
        self.pattern_library = pattern_library
        self.confidence_calculator = confidence_calculator
        self.pii_analyzer = NetworkPIIAnalyzer(
            pattern_library=pattern_library,
            confidence_calculator=confidence_calculator
        )
        logger.info("Configuration analyzer initialized")

    def analyze_configuration(self, file_path: str, content: str) -> FileAnalysisResult:
        """Analyze configuration files for PII."""
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=FileType.CONFIG_FILE,
            content_size=len(content),
            lines_analyzed=content.count('\n') + 1
        )
        
        try:
            # Use main PII analyzer for pattern detection
            result = self.pii_analyzer.analyze_content(content, file_path, FileType.CONFIG_FILE)
            
            # Additional configuration-specific analysis
            self._analyze_environment_variables(content, file_path, result)
            self._analyze_database_configurations(content, file_path, result)
            self._analyze_api_configurations(content, file_path, result)
            
        except Exception as e:
            logger.error(f"Error analyzing configuration {file_path}: {e}")
            result.analysis_successful = False
            result.error_message = str(e)
        
        return result

    def analyze_configuration_files(self, context: Any) -> List[FileAnalysisResult]:
        """Analyze configuration files in context."""
        results = []
        # Mock implementation - in real scenario would scan actual files
        logger.info("Analyzing configuration files...")
        return results

    def _analyze_environment_variables(self, content: str, file_path: str,
                                       result: FileAnalysisResult) -> None:
        """Analyze environment variables for sensitive data."""
        env_patterns = [
            (r'(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[=:]\s*["\']?([^"\'\s]+)', 'api_credential'),
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^"\'\s]+)', 'password'),
            (r'(?i)(username|user|login)\s*[=:]\s*["\']?([^"\'\s]+)', 'username'),
            (r'(?i)(database[_-]?url|db[_-]?url|connection[_-]?string)\s*[=:]\s*["\']?([^"\'\s]+)', 'database_url'),
            (r'(?i)(smtp[_-]?server|mail[_-]?server)\s*[=:]\s*["\']?([^"\'\s]+)', 'email_server'),
            (r'(?i)(redis[_-]?url|memcached[_-]?url)\s*[=:]\s*["\']?([^"\'\s]+)', 'cache_url')
        ]
        
        for pattern, cred_type in env_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                value = match.group(2)
                if len(value) > 3:  # Avoid false positives with very short values
                    if cred_type in ['api_credential', 'password']:
                        self._create_db_credential_finding(cred_type, value, file_path, result)
                    else:
                        self._create_api_config_finding(cred_type, value, file_path, result)

    def _analyze_database_configurations(self, content: str, file_path: str,
                                         result: FileAnalysisResult) -> None:
        """Analyze database configuration for credentials."""
        db_patterns = [
            r'(?:database|db)_(?:user|username|login)[:=]\s*([^\n]+)',
            r'(?:database|db)_(?:pass|password|pwd)[:=]\s*([^\n]+)',
            r'(?:database|db)_(?:host|server|url)[:=]\s*([^\n]+)',
            r'jdbc:[\w]+://([^/\s]+)',  # JDBC URLs
            r'mongodb://([^/\s]+)',  # MongoDB URLs
        ]
        
        for pattern in db_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1).strip().strip('"\'')
                if 'user' in pattern or 'login' in pattern:
                    self._create_db_credential_finding('username', value, file_path, result)
                elif 'pass' in pattern or 'pwd' in pattern:
                    self._create_db_credential_finding('password', value, file_path, result)
                elif 'host' in pattern or 'server' in pattern or 'url' in pattern:
                    self._create_db_credential_finding('connection_string', value, file_path, result)

    def _analyze_api_configurations(self, content: str, file_path: str,
                                    result: FileAnalysisResult) -> None:
        """Analyze API configuration for keys and endpoints."""
        api_patterns = [
            r'(?:api|auth)_key[:=]\s*([^\n]+)',
            r'(?:secret|token)[:=]\s*([^\n]+)',
            r'client_(?:id|secret)[:=]\s*([^\n]+)',
            r'(?:base|api)_url[:=]\s*([^\n]+)',
        ]
        
        for pattern in api_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1).strip().strip('"\'')
                
                if 'key' in pattern or 'secret' in pattern or 'token' in pattern:
                    self._create_api_config_finding('api_credential', value, file_path, result)
                elif 'url' in pattern:
                    self._create_api_config_finding('api_endpoint', value, file_path, result)

    def _is_sensitive_env_var(self, var_name: str) -> bool:
        """Check if environment variable name suggests sensitive data."""
        var_lower = var_name.lower()
        sensitive_indicators = [
            'key', 'secret', 'token', 'password', 'pwd', 'pass',
            'api_key', 'auth', 'credential', 'cert', 'private'
        ]
        
        return any(indicator in var_lower for indicator in sensitive_indicators)

    def _create_env_var_finding(self, var_name: str, var_value: str,
                                file_path: str, result: FileAnalysisResult) -> None:
        """Create finding for sensitive environment variable."""
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"{var_name}={var_value}"],
            context_factors=["environment_variable"],
            validation_checks={"is_sensitive_var": self._is_sensitive_env_var(var_name)},
            risk_factors=["env_var_exposure", "configuration_leakage"],
            data_sensitivity=["medium"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"env_var_{hash(f'{var_name}_{var_value}') % 10000:04d}",
            pii_type=PIIType.AUTHENTICATION_DATA,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.MEDIUM,
            confidence=self._calculate_confidence("environment_variable", evidence, 0.7),
            description=f"Sensitive environment variable '{var_name}' detected",
            location=file_path,
            evidence=f"{var_name}={var_value}",
            pattern_matched="environment_variable",
            matched_value=var_value,
            attack_vectors=["Environment variable exposure", "Configuration leakage"],
            privacy_impact="Medium - Sensitive credentials in environment variables",
            remediation="Use secure credential management systems instead of environment variables",
            masvs_control="MASVS-STORAGE-4",
            mstg_reference="MSTG-STORAGE-4"
        )
        
        result.pii_findings.append(finding)

    def _create_db_credential_finding(self, cred_type: str, value: str,
                                      file_path: str, result: FileAnalysisResult) -> None:
        """Create finding for database credentials."""
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"Database {cred_type}: {value}"],
            context_factors=["database_credentials"],
            validation_checks={"is_credential": True},
            risk_factors=["credential_exposure", "unauthorized_db_access"],
            data_sensitivity=["high"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"db_cred_{cred_type}_{hash(value) % 10000:04d}",
            pii_type=PIIType.AUTHENTICATION_DATA,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=SeverityLevel.HIGH,
            confidence=self._calculate_confidence("database_credentials", evidence, 0.8),
            description=f"Database {cred_type} detected in configuration",
            location=file_path,
            evidence=f"Database {cred_type}: {value}",
            pattern_matched="database_credential",
            matched_value=value,
            attack_vectors=["Database access", "Credential theft", "Data breach"],
            privacy_impact="High - Database credentials exposed in configuration",
            remediation="Use secure credential storage and database connection pooling",
            masvs_control="MASVS-STORAGE-4",
            mstg_reference="MSTG-STORAGE-4"
        )
        
        result.pii_findings.append(finding)

    def _create_api_config_finding(self, config_type: str, value: str,
                                   file_path: str, result: FileAnalysisResult) -> None:
        """Create finding for API configuration."""
        severity = SeverityLevel.HIGH if config_type == 'api_credential' else SeverityLevel.MEDIUM
        
        # Create evidence for professional confidence calculation
        evidence = ConfidenceEvidence(
            pattern_matches=[f"API {config_type}: {value}"],
            context_factors=["api_configuration"],
            validation_checks={"is_api_config": True, "is_credential": config_type == 'api_credential'},
            risk_factors=["api_abuse", "credential_theft", "service_impersonation"],
            data_sensitivity=["high" if config_type == 'api_credential' else "medium"]
        )
        
        finding = PIINetworkFinding(
            finding_id=f"api_config_{config_type}_{hash(value) % 10000:04d}",
            pii_type=PIIType.AUTHENTICATION_DATA if config_type == 'api_credential' else PIIType.NETWORK_IDENTIFIER,
            transmission_method=TransmissionMethod.UNKNOWN,
            severity=severity,
            confidence=self._calculate_confidence("api_configuration", evidence, 0.7),
            description=f"API {config_type} detected in configuration",
            location=file_path,
            evidence=f"API {config_type}: {value}",
            pattern_matched="api_configuration",
            matched_value=value,
            attack_vectors=["API abuse", "Credential theft", "Service impersonation"],
            privacy_impact=f"{'High' if config_type == 'api_credential' else 'Medium'} - API {config_type} in configuration",
            remediation="Use secure API key management and environment-specific configurations",
            masvs_control="MASVS-STORAGE-4",
            mstg_reference="MSTG-STORAGE-4"
        )
        
        result.pii_findings.append(finding)
        