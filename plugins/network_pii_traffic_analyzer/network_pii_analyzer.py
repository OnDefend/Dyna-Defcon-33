"""
Core Network PII Analyzer Module.

This module provides the main analysis logic for detecting personally identifiable
information (PII) in network communications, URL parameters, and configuration files.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Set, Any, Union
from pathlib import Path
import xml.etree.ElementTree as ET
import json

from .data_structures import (
    PIINetworkFinding, PIIPattern, PIIContext, NetworkEndpoint,
    PIIType, SeverityLevel, TransmissionMethod, FileType,
    AnalysisCategory, FileAnalysisResult, PIIAnalysisConfiguration,
    AnalysisError
)
from .pii_pattern_library import (
    get_pii_pattern_library, find_pii_in_text, extract_network_endpoints,
    categorize_transmission_risk
)
from .confidence_calculator import ConfidenceEvidence

logger = logging.getLogger(__name__)

class NetworkPIIAnalyzer:
    """Core analyzer for detecting PII in network communications."""
    
    def __init__(self, config: Optional[PIIAnalysisConfiguration] = None,
                 pattern_library: Optional[Any] = None,
                 confidence_calculator: Optional[Any] = None):
        """Initialize the Network PII Analyzer."""
        self.config = config or PIIAnalysisConfiguration()
        self.pattern_library = pattern_library or get_pii_pattern_library()
        self.confidence_calculator = confidence_calculator  # Can be None
        self.findings = []  # Track findings for analysis summary
        self.analysis_stats = {
            'files_analyzed': 0,
            'patterns_matched': 0,
            'urls_analyzed': 0,
            'parameters_checked': 0
        }
        
        logger.info("Network PII Analyzer initialized with professional confidence system")

    def _calculate_confidence(self, pattern: PIIPattern, evidence: ConfidenceEvidence, 
                            fallback_confidence: float = 0.7) -> float:
        """
        Calculate confidence using the professional confidence calculator if available,
        otherwise use fallback value.
        
        Args:
            pattern: PII pattern that was matched
            evidence: Evidence for confidence calculation
            fallback_confidence: Fallback confidence if calculator unavailable
            
        Returns:
            float: confidence score
        """
        if self.confidence_calculator:
            try:
                return self.confidence_calculator.calculate_confidence(pattern, evidence)
            except Exception as e:
                logger.warning(f"Confidence calculation failed, using fallback: {e}")
                return fallback_confidence
        else:
            logger.debug("No confidence calculator available, using fallback")
            return fallback_confidence

    def analyze_content(self, content: str, file_path: str, file_type: FileType) -> FileAnalysisResult:
        """
        Analyze content for PII patterns and network transmissions.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            file_type: Type of file being analyzed
            
        Returns:
            FileAnalysisResult containing findings and metadata
        """
        start_time = self._get_current_time()
        
        result = FileAnalysisResult(
            file_path=file_path,
            file_type=file_type,
            analysis_successful=True,
            content_size=len(content),
            lines_analyzed=content.count('\n') + 1
        )
        
        try:
            # Choose analysis depth based on configuration
            if self.config.enable_deep_analysis:
                self._deep_scan_content_for_pii(content, file_path, file_type, result)
            else:
                self._basic_scan_content_for_pii(content, file_path, file_type, result)
            
            # Extract network endpoints from content
            self._extract_network_endpoints(content, result)
            
            # Analyze WebView injection patterns
            if file_type in [FileType.SOURCE_CODE, FileType.CONFIG_FILE]:
                self._analyze_webview_injections(content, file_path, result)
            
            # Analyze configuration files for PII
            if file_type in [FileType.CONFIG_FILE, FileType.RESOURCE_FILE]:
                self._analyze_configuration_pii(content, file_path, result)
            
            # Update statistics
            self.analysis_stats['files_analyzed'] += 1
            result.analysis_duration = self._get_current_time() - start_time
            
            logger.info(f"Analyzed {file_path}: {len(result.pii_findings)} findings")
            
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            result.analysis_successful = False
            result.error_message = str(e)
            result.analysis_duration = self._get_current_time() - start_time
        
        return result

    def analyze_network_communications(self, context: 'PIIContext', 
                                      endpoints: List['NetworkEndpoint']) -> 'NetworkAnalysisResult':
        """
        Analyze network communications for PII patterns.
        
        Args:
            context: Analysis context containing configuration and metadata
            endpoints: List of network endpoints to analyze
            
        Returns:
            NetworkAnalysisResult with findings and analyzed endpoints
        """
        logger.debug(f"Analyzing {len(endpoints)} network endpoints for PII")
        
        # Create result container
        from collections import namedtuple
        NetworkAnalysisResult = namedtuple('NetworkAnalysisResult', ['network_findings', 'analyzed_endpoints'])
        
        network_findings = []
        analyzed_endpoints = []
        
        for endpoint in endpoints:
            try:
                # Analyze endpoint URL for PII patterns
                url_findings = self._analyze_endpoint_url(endpoint, context)
                network_findings.extend(url_findings)
                
                # Analyze endpoint parameters for PII
                param_findings = self._analyze_endpoint_parameters(endpoint, context)
                network_findings.extend(param_findings)
                
                # Mark endpoint as analyzed
                analyzed_endpoints.append(endpoint)
                
            except Exception as e:
                logger.warning(f"Failed to analyze endpoint {endpoint.url}: {e}")
                # Still include the endpoint but mark it as having issues
                analyzed_endpoints.append(endpoint)
        
        logger.debug(f"Network analysis completed: {len(network_findings)} findings from {len(analyzed_endpoints)} endpoints")
        
        return NetworkAnalysisResult(
            network_findings=network_findings,
            analyzed_endpoints=analyzed_endpoints
        )
    
    def _analyze_endpoint_url(self, endpoint: 'NetworkEndpoint', context: 'PIIContext') -> List['PIINetworkFinding']:
        """Analyze endpoint URL for PII patterns."""
        findings = []
        
        # Check if URL contains PII patterns
        url = getattr(endpoint, 'url', '')
        if url:
            # Use existing content analysis on the URL
            temp_result = self.analyze_content(url, f"endpoint:{url}", FileType.CONFIG_FILE)
            
            # Convert file findings to network findings
            for finding in temp_result.pii_findings:
                network_finding = self._convert_to_network_finding(finding, endpoint)
                findings.append(network_finding)
        
        return findings
    
    def _analyze_endpoint_parameters(self, endpoint: 'NetworkEndpoint', context: 'PIIContext') -> List['PIINetworkFinding']:
        """Analyze endpoint parameters for PII patterns."""
        findings = []
        
        # Check parameters if available
        parameters = getattr(endpoint, 'parameters', {})
        if parameters:
            for param_name, param_value in parameters.items():
                if isinstance(param_value, str):
                    # Analyze parameter value for PII
                    temp_result = self.analyze_content(param_value, f"parameter:{param_name}", FileType.CONFIG_FILE)
                    
                    # Convert findings to network findings
                    for finding in temp_result.pii_findings:
                        network_finding = self._convert_to_network_finding(finding, endpoint, param_name)
                        findings.append(network_finding)
        
        return findings
    
    def _convert_to_network_finding(self, finding: 'SecurityFinding', endpoint: 'NetworkEndpoint', 
                                   param_name: str = None) -> 'PIINetworkFinding':
        """Convert a security finding to a network PII finding."""
        from .data_structures import PIINetworkFinding, TransmissionMethod, PIIType, SeverityLevel
        
        # Determine transmission method based on endpoint
        url = getattr(endpoint, 'url', '')
        if url.startswith('https://'):
            transmission_method = TransmissionMethod.HTTPS
        elif url.startswith('http://'):
            transmission_method = TransmissionMethod.HTTP
        else:
            transmission_method = TransmissionMethod.OTHER
        
        # Create network finding
        network_finding = PIINetworkFinding(
            finding_id=f"net_{finding.finding_id}",
            pii_type=finding.finding_type if hasattr(finding, 'finding_type') else PIIType.OTHER,
            transmission_method=transmission_method,
            severity=finding.severity if hasattr(finding, 'severity') else SeverityLevel.MEDIUM,
            confidence=finding.confidence if hasattr(finding, 'confidence') else 0.7,
            description=f"PII detected in network endpoint{f' parameter {param_name}' if param_name else ''}",
            location=f"Network endpoint: {url}",
            evidence=finding.evidence if hasattr(finding, 'evidence') else str(finding),
            pattern_matched=finding.pattern_name if hasattr(finding, 'pattern_name') else "unknown",
            matched_value=finding.matched_value if hasattr(finding, 'matched_value') else "",
            remediation="Review network transmission of PII data and implement appropriate security measures",
            masvs_control="MASVS-NETWORK-1"
        )
        
        return network_finding

    def _deep_scan_content_for_pii(self, content: str, file_path: str, 
                                   file_type: FileType, result: FileAnalysisResult) -> None:
        """Perform deep scanning for PII patterns."""
        applicable_patterns = self._get_applicable_patterns(file_type)
        
        for pattern_name in applicable_patterns:
            pattern = self.pattern_library.get_pattern(pattern_name)
            if not pattern:
                continue
                
            try:
                # Find all matches for this pattern
                matches = re.finditer(pattern.pattern, content, 
                                    re.IGNORECASE if not pattern.case_sensitive else 0)
                
                for match in matches:
                    self._process_pii_match(pattern, match, content, file_path, file_type, result)
                    self.analysis_stats['patterns_matched'] += 1
                    
            except re.error as e:
                logger.warning(f"Invalid regex pattern {pattern_name}: {e}")
        
        # Scan for network URLs with PII parameters
        self._scan_network_urls_for_pii(content, file_path, file_type, result)

    def _basic_scan_content_for_pii(self, content: str, file_path: str,
                                    file_type: FileType, result: FileAnalysisResult) -> None:
        """Perform basic scanning for high-priority PII patterns only."""
        high_priority_patterns = [
            'android_id_transmission', 'imei_transmission', 'gps_coordinates',
            'api_key_pattern', 'jwt_token_pattern', 'email_pattern'
        ]
        
        for pattern_name in high_priority_patterns:
            pattern = self.pattern_library.get_pattern(pattern_name)
            if not pattern:
                continue
                
            try:
                matches = re.finditer(pattern.pattern, content, 
                                    re.IGNORECASE if not pattern.case_sensitive else 0)
                
                for match in matches:
                    self._process_pii_match(pattern, match, content, file_path, file_type, result)
                    self.analysis_stats['patterns_matched'] += 1
                    
            except re.error as e:
                logger.warning(f"Invalid regex pattern {pattern_name}: {e}")

    def _process_pii_match(self, pattern: PIIPattern, match: re.Match,
                           content: str, file_path: str, file_type: FileType,
                           result: FileAnalysisResult) -> None:
        """Process a matched PII pattern and create finding."""
        matched_value = match.group(0)
        
        # Validate match length
        if len(matched_value) < pattern.min_length or len(matched_value) > pattern.max_length:
            return
        
        # Extract context around the match
        context = self._extract_context(content, match.start(), match.end())
        
        # Detect transmission method
        transmission_method = self._detect_transmission_method(context)
        
        # Create PII context
        pii_context = self._create_pii_context(file_path, file_type, content, 
                                               match.start(), context)
        
        # Create finding
        finding = self._create_pii_finding(pattern, match, matched_value, file_path,
                                          file_type, transmission_method, context, pii_context)
        
        # Add to results
        result.pii_findings.append(finding)
        self.findings.append(finding)  # Track for summary

    def _scan_network_urls_for_pii(self, content: str, file_path: str,
                                   file_type: FileType, result: FileAnalysisResult) -> None:
        """Scan for network URLs that may contain PII in parameters."""
        # Pattern for URLs with parameters
        url_pattern = r'(https?://[^\s\'"]+\?[^\s\'"]*)'
        
        for url_match in re.finditer(url_pattern, content, re.IGNORECASE):
            self.analysis_stats['urls_analyzed'] += 1
            url = url_match.group(1)
            protocol = "HTTPS" if url.startswith('https') else "HTTP"
            
            self._analyze_url_parameters(url_match, protocol, content, file_path, file_type, result)

    def _analyze_url_parameters(self, url_match: re.Match, protocol: str,
                                content: str, file_path: str, file_type: FileType,
                                result: FileAnalysisResult) -> None:
        """Analyze URL parameters for PII."""
        url = url_match.group(1)
        
        # Extract parameters from URL
        if '?' in url:
            param_string = url.split('?', 1)[1]
            parameters = self._parse_url_parameters(param_string)
            
            for param_name, param_value in parameters.items():
                self.analysis_stats['parameters_checked'] += 1
                self._check_parameter_for_pii(param_name, param_value, url, protocol,
                                             content, file_path, file_type, result)

    def _check_parameter_for_pii(self, param_name: str, param_value: str,
                                 url: str, protocol: str, content: str,
                                 file_path: str, file_type: FileType,
                                 result: FileAnalysisResult) -> None:
        """Check if a URL parameter contains PII."""
        # Determine PII type from parameter name
        pii_type = self._determine_pii_type_from_param_name(param_name)
        
        if pii_type == PIIType.UNKNOWN:
            # Check parameter value against PII patterns
            for pattern_name in ['android_id_pattern', 'imei_pattern', 'gps_pattern', 
                               'email_pattern', 'phone_pattern']:
                pattern = self.pattern_library.get_pattern(pattern_name)
                if pattern and re.search(pattern.pattern, param_value, re.IGNORECASE):
                    pii_type = pattern.pii_type
                    break
        
        if pii_type != PIIType.UNKNOWN:
            # Create finding for PII in URL parameter
            transmission_method = TransmissionMethod.HTTPS if protocol == "HTTPS" else TransmissionMethod.HTTP
            
            # Create evidence for confidence calculation
            evidence = ConfidenceEvidence(
                pattern_id=f'url_parameter_{param_name}',
                matched_value=param_value,
                context=f"URL parameter: {param_name}",
                file_type=file_type,
                transmission_method=transmission_method,
                validation_sources=["url_parameter_extraction", "pattern_matching"],
                cross_references=[],
                additional_context={
                    'parameter_name': param_name,
                    'url_length': len(url),
                    'transmission_method': transmission_method.name,
                    'protocol': protocol
                }
            )
            
            # Create dummy pattern for confidence calculation
            dummy_pattern = PIIPattern(
                pattern_id=f'url_parameter_{param_name}',
                name=f'URL Parameter {param_name}',
                pattern='',
                pii_type=pii_type
            )
            
            # Calculate professional confidence
            confidence = self._calculate_confidence(
                pattern=dummy_pattern,
                evidence=evidence,
                fallback_confidence=0.8  # High confidence for parameter-based detection
            )
            
            finding = PIINetworkFinding(
                finding_id=f"url_param_{hash(f'{param_name}_{param_value}_{url}') % 10000:04d}",
                pii_type=pii_type,
                transmission_method=transmission_method,
                severity=SeverityLevel.HIGH if transmission_method == TransmissionMethod.HTTP else SeverityLevel.MEDIUM,
                confidence=confidence,
                description=f"PII detected in URL parameter '{param_name}'",
                location=file_path,
                evidence=f"URL: {url[:100]}{'...' if len(url) > 100 else ''}",
                pattern_matched=f"parameter:{param_name}",
                matched_value=param_value,
                attack_vectors=self._get_attack_vectors(pii_type, transmission_method),
                privacy_impact=self._get_privacy_impact(pii_type, transmission_method),
                remediation=self._get_remediation(pii_type, transmission_method),
                masvs_control="MASVS-NETWORK-1",
                mstg_reference="MSTG-NETWORK-1"
            )
            
            result.pii_findings.append(finding)
            self.findings.append(finding)

    def _extract_network_endpoints(self, content: str, result: FileAnalysisResult) -> None:
        """Extract network endpoints from content."""
        endpoints = extract_network_endpoints(content)
        result.network_endpoints.extend(endpoints)

    def _analyze_webview_injections(self, content: str, file_path: str,
                                    result: FileAnalysisResult) -> None:
        """Analyze WebView JavaScript injections for PII exposure."""
        # Pattern for WebView addJavascriptInterface calls
        webview_pattern = r'addJavascriptInterface\s*\([^)]+\)'
        
        for match in re.finditer(webview_pattern, content, re.IGNORECASE):
            injection_code = match.group(0)
            
            # Check if the injection contains PII patterns
            for pattern_name in ['android_id_pattern', 'device_info_pattern', 'location_pattern']:
                pattern = self.pattern_library.get_pattern(pattern_name)
                if pattern and re.search(pattern.pattern, injection_code, re.IGNORECASE):
                    
                    # Create evidence for confidence calculation
                    evidence = ConfidenceEvidence(
                        pattern_id=pattern.pattern_id if hasattr(pattern, 'pattern_id') else pattern_name,
                        matched_value=injection_code,
                        context="WebView JavaScript injection",
                        file_type=FileType.SOURCE_CODE,
                        transmission_method=TransmissionMethod.WEBSOCKET,
                        validation_sources=["webview_pattern_matching", "javascript_analysis"],
                        cross_references=[],
                        additional_context={
                            'injection_type': 'addJavascriptInterface',
                            'pattern_name': pattern_name,
                            'code_length': len(injection_code)
                        }
                    )
                    
                    # Calculate professional confidence
                    confidence = self._calculate_confidence(
                        pattern=pattern,
                        evidence=evidence,
                        fallback_confidence=0.7  # Medium-high confidence for WebView injection
                    )
                    
                    finding = PIINetworkFinding(
                        finding_id=f"webview_injection_{hash(injection_code) % 10000:04d}",
                        pii_type=pattern.pii_type,
                        transmission_method=TransmissionMethod.WEBSOCKET,  # Assuming WebSocket for WebView
                        severity=SeverityLevel.HIGH,
                        confidence=confidence,
                        description=f"PII detected in WebView JavaScript injection",
                        location=file_path,
                        evidence=injection_code,
                        pattern_matched=pattern.name,
                        attack_vectors=["JavaScript injection attack", "Cross-site scripting (XSS)", "Data exfiltration"],
                        privacy_impact="High - PII exposed through WebView interface",
                        remediation="Sanitize data before JavaScript interface injection",
                        masvs_control="MASVS-PLATFORM-2",
                        mstg_reference="MSTG-PLATFORM-2"
                    )
                    
                    result.pii_findings.append(finding)

    def _analyze_configuration_pii(self, content: str, file_path: str,
                                   result: FileAnalysisResult) -> None:
        """Analyze configuration files for PII."""
        try:
            # Try to parse as JSON
            if file_path.endswith('.json'):
                config_data = json.loads(content)
                self._analyze_json_config_for_pii(config_data, file_path, result)
            
            # Try to parse as XML
            elif file_path.endswith('.xml'):
                root = ET.fromstring(content)
                self._analyze_xml_config_for_pii(root, file_path, result)
            
            # Analyze as text-based configuration
            else:
                self._analyze_text_config_for_pii(content, file_path, result)
                
        except (json.JSONDecodeError, ET.ParseError) as e:
            logger.debug(f"Could not parse {file_path} as structured config: {e}")
            # Fallback to text analysis
            self._analyze_text_config_for_pii(content, file_path, result)

    def _analyze_json_config_for_pii(self, config_data: Dict[str, Any],
                                     file_path: str, result: FileAnalysisResult) -> None:
        """Analyze JSON configuration for PII."""
        def check_json_value(key: str, value: Any, path: str = "") -> None:
            current_path = f"{path}.{key}" if path else key
            
            if isinstance(value, str):
                # Check string values against PII patterns
                for pattern_name in ['email_pattern', 'phone_pattern', 'api_key_pattern', 
                                   'android_id_pattern', 'gps_pattern']:
                    pattern = self.pattern_library.get_pattern(pattern_name)
                    if pattern and re.search(pattern.pattern, value, re.IGNORECASE):
                        finding = PIINetworkFinding(
                            finding_id=f"config_pii_{hash(f'{current_path}_{value}') % 10000:04d}",
                            pii_type=pattern.pii_type,
                            transmission_method=TransmissionMethod.UNKNOWN,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.6,
                            description=f"PII detected in configuration key '{current_path}'",
                            location=file_path,
                            evidence=f"{key}: {value}",
                            pattern_matched=pattern.name,
                            matched_value=value,
                            attack_vectors=["Configuration exposure", "Data leakage"],
                            privacy_impact="Medium - PII in configuration files",
                            remediation="Remove or encrypt PII in configuration files",
                            masvs_control="MASVS-STORAGE-4",
                            mstg_reference="MSTG-STORAGE-4"
                        )
                        
                        result.pii_findings.append(finding)
            
            elif isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    check_json_value(sub_key, sub_value, current_path)
            
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, (dict, str)):
                        check_json_value(f"{key}[{i}]", item, path)
        
        if isinstance(config_data, dict):
            for key, value in config_data.items():
                check_json_value(key, value)

    def _analyze_xml_config_for_pii(self, root: ET.Element, file_path: str,
                                    result: FileAnalysisResult) -> None:
        """Analyze XML configuration for PII."""
        def check_xml_element(element: ET.Element, path: str = "") -> None:
            current_path = f"{path}/{element.tag}" if path else element.tag
            
            # Check element text
            if element.text and element.text.strip():
                text_content = element.text.strip()
                
                for pattern_name in ['email_pattern', 'phone_pattern', 'api_key_pattern',
                                   'android_id_pattern', 'gps_pattern']:
                    pattern = self.pattern_library.get_pattern(pattern_name)
                    if pattern and re.search(pattern.pattern, text_content, re.IGNORECASE):
                        finding = PIINetworkFinding(
                            finding_id=f"xml_config_pii_{hash(f'{current_path}_{text_content}') % 10000:04d}",
                            pii_type=pattern.pii_type,
                            transmission_method=TransmissionMethod.UNKNOWN,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.6,
                            description=f"PII detected in XML element '{current_path}'",
                            location=file_path,
                            evidence=f"<{element.tag}>{text_content}</{element.tag}>",
                            pattern_matched=pattern.name,
                            matched_value=text_content,
                            attack_vectors=["XML configuration exposure", "Data leakage"],
                            privacy_impact="Medium - PII in XML configuration",
                            remediation="Remove or encrypt PII in XML configuration",
                            masvs_control="MASVS-STORAGE-4",
                            mstg_reference="MSTG-STORAGE-4"
                        )
                        
                        result.pii_findings.append(finding)
            
            # Check attributes
            for attr_name, attr_value in element.attrib.items():
                for pattern_name in ['email_pattern', 'phone_pattern', 'api_key_pattern']:
                    pattern = self.pattern_library.get_pattern(pattern_name)
                    if pattern and re.search(pattern.pattern, attr_value, re.IGNORECASE):
                        finding = PIINetworkFinding(
                            finding_id=f"xml_attr_pii_{hash(f'{current_path}@{attr_name}_{attr_value}') % 10000:04d}",
                            pii_type=pattern.pii_type,
                            transmission_method=TransmissionMethod.UNKNOWN,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.6,
                            description=f"PII detected in XML attribute '{current_path}@{attr_name}'",
                            location=file_path,
                            evidence=f"{attr_name}=\"{attr_value}\"",
                            pattern_matched=pattern.name,
                            matched_value=attr_value,
                            attack_vectors=["XML attribute exposure", "Data leakage"],
                            privacy_impact="Medium - PII in XML attributes",
                            remediation="Remove or encrypt PII in XML attributes",
                            masvs_control="MASVS-STORAGE-4",
                            mstg_reference="MSTG-STORAGE-4"
                        )
                        
                        result.pii_findings.append(finding)
            
            # Recursively check child elements
            for child in element:
                check_xml_element(child, current_path)
        
        check_xml_element(root)

    def _analyze_text_config_for_pii(self, content: str, file_path: str,
                                     result: FileAnalysisResult) -> None:
        """Analyze text-based configuration files for PII."""
        # Look for key-value pairs in various formats
        config_patterns = [
            r'(\w+)\s*[=:]\s*([^\r\n]+)',  # key=value or key: value
            r'(\w+)\s*[=:]\s*["\']([^"\']+)["\']',  # quoted values
            r'<(\w+)>([^<]+)</\w+>',  # XML-like tags
        ]
        
        for config_pattern in config_patterns:
            for match in re.finditer(config_pattern, content, re.IGNORECASE):
                key = match.group(1)
                value = match.group(2)
                
                # Check value against PII patterns
                for pattern_name in ['email_pattern', 'phone_pattern', 'api_key_pattern',
                                   'android_id_pattern', 'gps_pattern']:
                    pattern = self.pattern_library.get_pattern(pattern_name)
                    if pattern and re.search(pattern.pattern, value, re.IGNORECASE):
                        finding = PIINetworkFinding(
                            finding_id=f"text_config_pii_{hash(f'{key}_{value}') % 10000:04d}",
                            pii_type=pattern.pii_type,
                            transmission_method=TransmissionMethod.UNKNOWN,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.5,
                            description=f"PII detected in configuration key '{key}'",
                            location=file_path,
                            evidence=f"{key}={value}",
                            pattern_matched=pattern.name,
                            matched_value=value,
                            attack_vectors=["Configuration file exposure", "Data leakage"],
                            privacy_impact="Medium - PII in text configuration",
                            remediation="Remove or encrypt PII in configuration files",
                            masvs_control="MASVS-STORAGE-4",
                            mstg_reference="MSTG-STORAGE-4"
                        )
                        
                        result.pii_findings.append(finding)

    def _get_applicable_patterns(self, file_type: FileType) -> List[str]:
        """Get list of applicable PII patterns for file type."""
        all_patterns = [
            'android_id_transmission', 'imei_transmission', 'advertising_id_pattern',
            'device_fingerprint_pattern', 'gps_coordinates', 'location_address_pattern',
            'postal_code_pattern', 'mac_address_pattern', 'ip_address_pattern',
            'dns_address_pattern', 'ssid_pattern', 'phone_number_pattern',
            'email_pattern', 'name_pattern', 'ssn_pattern', 'api_key_pattern',
            'password_pattern', 'jwt_token_pattern', 'biometric_template_pattern',
            'behavior_pattern', 'http_transmission_pattern', 'https_transmission_pattern',
            'websocket_transmission_pattern'
        ]
        
        if file_type == FileType.SOURCE_CODE:
            return all_patterns
        elif file_type == FileType.RESOURCE_FILE:
            return ['api_key_pattern', 'email_pattern', 'phone_number_pattern', 
                   'gps_coordinates', 'http_transmission_pattern', 'https_transmission_pattern']
        elif file_type == FileType.CONFIG_FILE:
            return ['api_key_pattern', 'password_pattern', 'jwt_token_pattern',
                   'email_pattern', 'android_id_pattern', 'gps_coordinates']
        elif file_type == FileType.MANIFEST:
            return ['android_id_pattern', 'device_fingerprint_pattern', 'permission_patterns']
        else:
            return ['email_pattern', 'phone_number_pattern', 'api_key_pattern']

    def _extract_context(self, content: str, start: int, end: int, 
                         context_size: int = 100) -> str:
        """Extract context around a match."""
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        return content[context_start:context_end]

    def _detect_transmission_method(self, context: str) -> TransmissionMethod:
        """Detect transmission method from context."""
        context_lower = context.lower()
        
        if any(method in context_lower for method in ['https://', 'ssl', 'tls']):
            return TransmissionMethod.HTTPS
        elif any(method in context_lower for method in ['http://', 'websocket', 'ws://']):
            return TransmissionMethod.HTTP
        elif 'websocket' in context_lower or 'ws://' in context_lower:
            return TransmissionMethod.WEBSOCKET
        elif any(method in context_lower for method in ['ftp://', 'sftp://']):
            return TransmissionMethod.FTP
        elif any(method in context_lower for method in ['sms', 'sendtextmessage']):
            return TransmissionMethod.SMS
        elif any(method in context_lower for method in ['email', 'mailto']):
            return TransmissionMethod.EMAIL
        else:
            return TransmissionMethod.UNKNOWN

    def _create_pii_context(self, file_path: str, file_type: FileType, 
                            content: str, match_start: int, context: str) -> PIIContext:
        """Create PII context for a finding."""
        # Find line number
        line_number = content[:match_start].count('\n') + 1
        
        # Extract method and class names for source files
        method_name = None
        class_name = None
        
        if file_type == FileType.SOURCE_CODE:
            method_name = self._extract_method_name(content, match_start)
            class_name = self._extract_class_name(content, match_start)
        
        return PIIContext(
            file_path=file_path,
            file_type=file_type,
            line_number=line_number,
            surrounding_code=context,
            method_name=method_name,
            class_name=class_name
        )

    def _create_pii_finding(self, pattern: PIIPattern, match: re.Match,
                            matched_value: str, file_path: str, file_type: FileType,
                            transmission_method: TransmissionMethod, context: str,
                            pii_context: PIIContext) -> PIINetworkFinding:
        """Create a PII finding from pattern match."""
        finding_id = f"pii_{pattern.pii_type.value}_{hash(f'{file_path}_{matched_value}_{match.start()}') % 10000:04d}"
        
        # Calculate confidence using the professional confidence calculator if available
        confidence = 0.7 # Default confidence
        if self.confidence_calculator:
            try:
                evidence = ConfidenceEvidence(
                    pattern_id=pattern.pattern_id if hasattr(pattern, 'pattern_id') else pattern.name,
                    matched_value=matched_value,
                    context=f"PII match in {file_path}",
                    file_type=file_type,
                    transmission_method=transmission_method,
                    validation_sources=["pattern_matching"],
                    cross_references=[],
                    additional_context={
                        'pattern_name': pattern.name,
                        'file_path': file_path,
                        'match_start': match.start(),
                        'match_end': match.end()
                    }
                )
                confidence = self.confidence_calculator.calculate_confidence(pattern, evidence)
            except Exception as e:
                logger.warning(f"Confidence calculation failed for pattern {pattern.name}, using fallback: {e}")
        
        return PIINetworkFinding(
            finding_id=finding_id,
            pii_type=pattern.pii_type,
            transmission_method=transmission_method,
            severity=pattern.severity,
            confidence=confidence,
            description=pattern.description,
            location=file_path,
            evidence=matched_value,
            pattern_matched=pattern.name,
            matched_value=matched_value,
            context=pii_context,
            attack_vectors=self._get_attack_vectors(pattern.pii_type, transmission_method),
            privacy_impact=self._get_privacy_impact(pattern.pii_type, transmission_method),
            remediation=self._get_remediation(pattern.pii_type, transmission_method),
            masvs_control=pattern.masvs_controls[0] if pattern.masvs_controls else "MASVS-NETWORK-1",
            mstg_reference="MSTG-NETWORK-1"
        )

    def _parse_url_parameters(self, param_string: str) -> Dict[str, str]:
        """Parse URL parameters from parameter string."""
        parameters = {}
        
        for param in param_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                parameters[key.strip()] = value.strip()
        
        return parameters

    def _determine_pii_type_from_param_name(self, param_name: str) -> PIIType:
        """Determine PII type from parameter name."""
        param_lower = param_name.lower()
        
        if any(term in param_lower for term in ['android_id', 'device_id', 'androidid']):
            return PIIType.DEVICE_IDENTIFIER
        elif any(term in param_lower for term in ['imei', 'device_imei']):
            return PIIType.DEVICE_IDENTIFIER
        elif any(term in param_lower for term in ['lat', 'latitude', 'lng', 'longitude', 'location']):
            return PIIType.LOCATION_DATA
        elif any(term in param_lower for term in ['email', 'mail']):
            return PIIType.PERSONAL_IDENTIFIER
        elif any(term in param_lower for term in ['phone', 'tel', 'mobile']):
            return PIIType.PERSONAL_IDENTIFIER
        elif any(term in param_lower for term in ['api_key', 'apikey', 'key', 'token']):
            return PIIType.AUTHENTICATION_DATA
        elif any(term in param_lower for term in ['mac', 'wifi_mac', 'bluetooth_mac']):
            return PIIType.NETWORK_IDENTIFIER
        else:
            return PIIType.UNKNOWN

    def _extract_method_name(self, content: str, position: int) -> Optional[str]:
        """Extract method name from source code context."""
        # Look backwards for method declaration
        lines_before = content[:position].split('\n')
        
        for line in reversed(lines_before[-10:]):  # Check last 10 lines
            # Java/Kotlin method patterns
            method_patterns = [
                r'\b(?:public|private|protected|static)?\s*(?:void|int|String|boolean|[A-Z]\w*)\s+(\w+)\s*\(',
                r'\bfun\s+(\w+)\s*\(',  # Kotlin function
            ]
            
            for pattern in method_patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
        
        return None

    def _extract_class_name(self, content: str, position: int) -> Optional[str]:
        """Extract class name from source code context."""
        # Look backwards for class declaration
        lines_before = content[:position].split('\n')
        
        for line in reversed(lines_before):
            # Java/Kotlin class patterns
            class_patterns = [
                r'\bclass\s+(\w+)',
                r'\bobject\s+(\w+)',  # Kotlin object
                r'\binterface\s+(\w+)',
            ]
            
            for pattern in class_patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
        
        return None

    def _get_attack_vectors(self, pii_type: PIIType, transmission_method: TransmissionMethod) -> List[str]:
        """Get potential attack vectors for PII type and transmission method."""
        vectors = []
        
        # Base vectors by PII type
        if pii_type == PIIType.DEVICE_IDENTIFIER:
            vectors.extend(["Device tracking", "Fingerprinting attack", "User profiling"])
        elif pii_type == PIIType.LOCATION_DATA:
            vectors.extend(["Location tracking", "Geostalking", "Movement pattern analysis"])
        elif pii_type == PIIType.PERSONAL_IDENTIFIER:
            vectors.extend(["Identity theft", "Social engineering", "Phishing attacks"])
        elif pii_type == PIIType.AUTHENTICATION_DATA:
            vectors.extend(["Credential theft", "Session hijacking", "API abuse"])
        elif pii_type == PIIType.NETWORK_IDENTIFIER:
            vectors.extend(["Network reconnaissance", "MAC address tracking", "Network profiling"])
        
        # Additional vectors by transmission method
        if transmission_method == TransmissionMethod.HTTP:
            vectors.extend(["Man-in-the-middle attack", "Network eavesdropping", "Traffic interception"])
        elif transmission_method == TransmissionMethod.SMS:
            vectors.extend(["SMS interception", "SIM swapping", "SMS spoofing"])
        elif transmission_method == TransmissionMethod.EMAIL:
            vectors.extend(["Email interception", "Email spoofing", "SMTP hijacking"])
        
        return vectors

    def _get_remediation(self, pii_type: PIIType, transmission_method: TransmissionMethod) -> str:
        """Get remediation advice for PII type and transmission method."""
        base_remediation = {
            PIIType.DEVICE_IDENTIFIER: "Use privacy-preserving identifiers or obtain explicit user consent",
            PIIType.LOCATION_DATA: "Implement location data minimization and user consent mechanisms",
            PIIType.PERSONAL_IDENTIFIER: "Encrypt sensitive personal data and implement proper access controls",
            PIIType.AUTHENTICATION_DATA: "Use secure authentication protocols and proper credential management",
            PIIType.NETWORK_IDENTIFIER: "Avoid collecting network identifiers unless absolutely necessary"
        }.get(pii_type, "Review data collection practices and implement appropriate privacy controls")
        
        if transmission_method == TransmissionMethod.HTTP:
            base_remediation += ". CRITICAL: Use HTTPS encryption for all network transmissions."
        elif transmission_method == TransmissionMethod.SMS:
            base_remediation += ". Consider encrypted messaging alternatives to SMS."
        
        return base_remediation

    def _get_privacy_impact(self, pii_type: PIIType, transmission_method: TransmissionMethod) -> str:
        """Get privacy impact description."""
        impact_levels = {
            PIIType.AUTHENTICATION_DATA: "Critical",
            PIIType.PERSONAL_IDENTIFIER: "High",
            PIIType.BIOMETRIC_DATA: "Critical",
            PIIType.LOCATION_DATA: "High",
            PIIType.DEVICE_IDENTIFIER: "Medium",
            PIIType.BEHAVIORAL_DATA: "Medium",
            PIIType.NETWORK_IDENTIFIER: "Low",
            PIIType.SYSTEM_IDENTIFIER: "Low"
        }
        
        impact = impact_levels.get(pii_type, "Medium")
        
        if transmission_method == TransmissionMethod.HTTP:
            impact = "Critical"  # Unencrypted transmission escalates impact
        
        return f"{impact} privacy impact - {pii_type.value.replace('_', ' ')} transmitted via {transmission_method.value.upper()}"

    def _get_current_time(self) -> float:
        """Get current time for performance measurement."""
        import time
        return time.time()

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of analysis results."""
        return {
            'total_findings': len(self.findings),
            'findings_by_severity': self._get_findings_by_severity(),
            'findings_by_pii_type': self._get_findings_by_pii_type(),
            'findings_by_transmission_method': self._get_findings_by_transmission_method(),
            'analysis_stats': self.analysis_stats.copy()
        }

    def _get_findings_by_severity(self) -> Dict[str, int]:
        """Get findings count by severity."""
        counts = {severity.value: 0 for severity in SeverityLevel}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def _get_findings_by_pii_type(self) -> Dict[str, int]:
        """Get findings count by PII type."""
        counts = {pii_type.value: 0 for pii_type in PIIType}
        for finding in self.findings:
            counts[finding.pii_type.value] += 1
        return counts

    def _get_findings_by_transmission_method(self) -> Dict[str, int]:
        """Get findings count by transmission method."""
        counts = {method.value: 0 for method in TransmissionMethod}
        for finding in self.findings:
            counts[finding.transmission_method.value] += 1
        return counts

    def reset_findings(self) -> None:
        """Reset findings for new analysis."""
        self.findings.clear()
        self.analysis_stats = {
            'files_analyzed': 0,
            'patterns_matched': 0,
            'urls_analyzed': 0,
            'parameters_checked': 0
        }
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
        
        return None

    def _get_attack_vectors(self, pii_type: PIIType, transmission_method: TransmissionMethod) -> List[str]:
        """Get potential attack vectors for PII type and transmission method."""
        vectors = []
        
        # Base vectors by PII type
        if pii_type == PIIType.DEVICE_IDENTIFIER:
            vectors.extend(["Device tracking", "Fingerprinting attack", "User profiling"])
        elif pii_type == PIIType.LOCATION_DATA:
            vectors.extend(["Location tracking", "Geostalking", "Movement pattern analysis"])
        elif pii_type == PIIType.PERSONAL_IDENTIFIER:
            vectors.extend(["Identity theft", "Social engineering", "Phishing attacks"])
        elif pii_type == PIIType.AUTHENTICATION_DATA:
            vectors.extend(["Credential theft", "Session hijacking", "API abuse"])
        elif pii_type == PIIType.NETWORK_IDENTIFIER:
            vectors.extend(["Network reconnaissance", "MAC address tracking", "Network profiling"])
        
        # Additional vectors by transmission method
        if transmission_method == TransmissionMethod.HTTP:
            vectors.extend(["Man-in-the-middle attack", "Network eavesdropping", "Traffic interception"])
        elif transmission_method == TransmissionMethod.SMS:
            vectors.extend(["SMS interception", "SIM swapping", "SMS spoofing"])
        elif transmission_method == TransmissionMethod.EMAIL:
            vectors.extend(["Email interception", "Email spoofing", "SMTP hijacking"])
        
        return vectors

    def _get_remediation(self, pii_type: PIIType, transmission_method: TransmissionMethod) -> str:
        """Get remediation advice for PII type and transmission method."""
        base_remediation = {
            PIIType.DEVICE_IDENTIFIER: "Use privacy-preserving identifiers or obtain explicit user consent",
            PIIType.LOCATION_DATA: "Implement location data minimization and user consent mechanisms",
            PIIType.PERSONAL_IDENTIFIER: "Encrypt sensitive personal data and implement proper access controls",
            PIIType.AUTHENTICATION_DATA: "Use secure authentication protocols and proper credential management",
            PIIType.NETWORK_IDENTIFIER: "Avoid collecting network identifiers unless absolutely necessary"
        }.get(pii_type, "Review data collection practices and implement appropriate privacy controls")
        
        if transmission_method == TransmissionMethod.HTTP:
            base_remediation += ". CRITICAL: Use HTTPS encryption for all network transmissions."
        elif transmission_method == TransmissionMethod.SMS:
            base_remediation += ". Consider encrypted messaging alternatives to SMS."
        
        return base_remediation

    def _get_privacy_impact(self, pii_type: PIIType, transmission_method: TransmissionMethod) -> str:
        """Get privacy impact description."""
        impact_levels = {
            PIIType.AUTHENTICATION_DATA: "Critical",
            PIIType.PERSONAL_IDENTIFIER: "High",
            PIIType.BIOMETRIC_DATA: "Critical",
            PIIType.LOCATION_DATA: "High",
            PIIType.DEVICE_IDENTIFIER: "Medium",
            PIIType.BEHAVIORAL_DATA: "Medium",
            PIIType.NETWORK_IDENTIFIER: "Low",
            PIIType.SYSTEM_IDENTIFIER: "Low"
        }
        
        impact = impact_levels.get(pii_type, "Medium")
        
        if transmission_method == TransmissionMethod.HTTP:
            impact = "Critical"  # Unencrypted transmission escalates impact
        
        return f"{impact} privacy impact - {pii_type.value.replace('_', ' ')} transmitted via {transmission_method.value.upper()}"

    def _get_current_time(self) -> float:
        """Get current time for performance measurement."""
        import time
        return time.time()

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of analysis results."""
        return {
            'total_findings': len(self.findings),
            'findings_by_severity': self._get_findings_by_severity(),
            'findings_by_pii_type': self._get_findings_by_pii_type(),
            'findings_by_transmission_method': self._get_findings_by_transmission_method(),
            'analysis_stats': self.analysis_stats.copy()
        }

    def _get_findings_by_severity(self) -> Dict[str, int]:
        """Get findings count by severity."""
        counts = {severity.value: 0 for severity in SeverityLevel}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def _get_findings_by_pii_type(self) -> Dict[str, int]:
        """Get findings count by PII type."""
        counts = {pii_type.value: 0 for pii_type in PIIType}
        for finding in self.findings:
            counts[finding.pii_type.value] += 1
        return counts

    def _get_findings_by_transmission_method(self) -> Dict[str, int]:
        """Get findings count by transmission method."""
        counts = {method.value: 0 for method in TransmissionMethod}
        for finding in self.findings:
            counts[finding.transmission_method.value] += 1
        return counts

    def reset_findings(self) -> None:
        """Reset findings for new analysis."""
        self.findings.clear()
        self.analysis_stats = {
            'files_analyzed': 0,
            'patterns_matched': 0,
            'urls_analyzed': 0,
            'parameters_checked': 0
        }