#!/usr/bin/env python3
"""
APK2URL Extraction Plugin - URL Extractor

Core URL and endpoint extraction engine implementing multiple extraction techniques:
- Manifest analysis for network configurations and URLs
- Resource file analysis (strings.xml, config files)  
- DEX file analysis for hardcoded endpoints
- Native library analysis for embedded URLs
- Certificate analysis for endpoint discovery
- Binary pattern matching for various URL formats
"""

import logging
import re
import json
import xml.etree.ElementTree as ET
import zipfile
import base64
import time
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime

from .data_structures import (
    EndpointFinding, EndpointType, ExtractionMethod, SecurityRisk,
    ProtocolType, DomainCategory, ExtractionResults, ExtractionStatistics,
    ExtractionContext, PatternMatch, DEFAULT_PROCESSING_LIMITS
)
from .confidence_calculator import APK2URLConfidenceCalculator
from .pattern_analyzer import PatternAnalyzer
from .noise_filter import NoiseFilter

logger = logging.getLogger(__name__)

class URLExtractor:
    """
    Core URL and endpoint extraction engine.
    
    Implements multiple extraction techniques with noise filtering
    and professional confidence calculation.
    """
    
    def __init__(self, apk_path: Path, config: Dict[str, Any], plugin_version: str = "2.0.0"):
        """Initialize URL extractor with APK path and configuration."""
        self.apk_path = apk_path
        self.config = config
        self.plugin_version = plugin_version
        
        # Initialize processing limits
        self.processing_limits = DEFAULT_PROCESSING_LIMITS.copy()
        if 'processing_limits' in config:
            self.processing_limits.update(config['processing_limits'])
        
        # Initialize analysis components
        self.confidence_calculator = APK2URLConfidenceCalculator()
        self.pattern_analyzer = PatternAnalyzer(config)
        self.noise_filter = NoiseFilter(config)
        
        # Extraction context
        apk_size = apk_path.stat().st_size if apk_path.exists() else 0
        self.extraction_context = ExtractionContext(
            apk_path=apk_path,
            apk_size=apk_size,
            is_large_apk=apk_size > (self.processing_limits['max_file_size_mb'] * 1024 * 1024),
            max_processing_time=self.processing_limits['max_processing_time'],
            extraction_timestamp=datetime.now(),
            plugin_version=self.plugin_version,
            processing_limits=self.processing_limits
        )
        
        # Extraction statistics
        self.stats = {
            'total_files_processed': 0,
            'dex_files_processed': 0,
            'resource_files_processed': 0,
            'native_libs_processed': 0,
            'certificates_processed': 0,
            'extraction_duration': 0.0,
            'total_findings': 0,
            'unique_endpoints': 0,
            'noise_filtered': 0,
            'processing_errors': 0
        }
        
        # Raw findings storage
        self.raw_findings = {
            'urls': set(),
            'ips': set(),
            'domains': set(),
            'api_endpoints': set(),
            'deep_links': set(),
            'file_urls': set(),
            'certificates': set(),
            'secrets': set()
        }
        
        # Detailed findings with metadata
        self.detailed_findings = []
        
        logger.info(f"Initialized URLExtractor for APK: {apk_path}")
    
    def extract_endpoints(self) -> ExtractionResults:
        """
        Perform comprehensive endpoint extraction from APK.
        
        Returns:
            ExtractionResults with categorized findings and metadata
        """
        start_time = time.time()
        
        try:
            logger.info("Starting comprehensive endpoint extraction")
            
            # Open APK as ZIP file for analysis
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                # Extract from different APK components
                self._extract_from_manifest(apk_zip)
                self._extract_from_resources(apk_zip)
                self._extract_from_dex_files(apk_zip)
                self._extract_from_configs(apk_zip) 
                self._extract_from_native_libs(apk_zip)
                self._extract_from_certificates(apk_zip)
            
            # Apply noise filtering
            filtered_results = self._apply_noise_filtering()
            
            # Calculate statistics
            extraction_duration = time.time() - start_time
            self.stats['extraction_duration'] = extraction_duration
            self.stats['total_findings'] = sum(len(category) for category in self.raw_findings.values())
            self.stats['unique_endpoints'] = len(set().union(*self.raw_findings.values()))
            
            # Create extraction statistics
            extraction_stats = ExtractionStatistics(
                total_files_processed=self.stats['total_files_processed'],
                dex_files_processed=self.stats['dex_files_processed'],
                resource_files_processed=self.stats['resource_files_processed'],
                native_libs_processed=self.stats['native_libs_processed'],
                certificates_processed=self.stats['certificates_processed'],
                extraction_duration=extraction_duration,
                total_findings=self.stats['total_findings'],
                unique_endpoints=self.stats['unique_endpoints'],
                noise_filtered=self.stats['noise_filtered'],
                processing_errors=self.stats['processing_errors']
            )
            
            # Build final results
            results = ExtractionResults(
                urls=filtered_results['urls'],
                ips=filtered_results['ips'],
                domains=filtered_results['domains'],
                api_endpoints=filtered_results['api_endpoints'],
                deep_links=filtered_results['deep_links'],
                file_urls=filtered_results['file_urls'],
                certificates=filtered_results['certificates'],
                secrets=filtered_results['secrets'],
                detailed_findings=self.detailed_findings,
                statistics=extraction_stats,
                extraction_context=self.extraction_context
            )
            
            logger.info(f"Extraction completed in {extraction_duration:.2f}s, found {self.stats['total_findings']} endpoints")
            return results
            
        except Exception as e:
            logger.error(f"Error during endpoint extraction: {e}")
            self.stats['processing_errors'] += 1
            
            # Return partial results even on error
            return ExtractionResults(
                processing_errors=[str(e)],
                extraction_context=self.extraction_context
            )
    
    def _extract_from_manifest(self, apk_zip: zipfile.ZipFile) -> None:
        """Extract endpoints from AndroidManifest.xml."""
        try:
            if 'AndroidManifest.xml' not in apk_zip.namelist():
                logger.warning("AndroidManifest.xml not found in APK")
                return
            
            logger.debug("Extracting from AndroidManifest.xml")
            
            # Read and parse manifest
            manifest_data = apk_zip.read('AndroidManifest.xml')
            manifest_text = self._extract_strings_from_binary(manifest_data)
            
            # Extract patterns from manifest text
            self._extract_patterns_from_text(
                manifest_text, 
                'AndroidManifest.xml',
                ExtractionMethod.MANIFEST_ANALYSIS
            )
            
            self.stats['total_files_processed'] += 1
            logger.debug("Completed manifest analysis")
            
        except Exception as e:
            logger.error(f"Error extracting from manifest: {e}")
            self.stats['processing_errors'] += 1
    
    def _extract_from_resources(self, apk_zip: zipfile.ZipFile) -> None:
        """Extract endpoints from resource files."""
        try:
            logger.debug("Extracting from resource files")
            
            # Get resource files with size limits
            resource_files = [
                f for f in apk_zip.namelist()
                if (f.startswith('res/') and 
                    (f.endswith('.xml') or f.endswith('.json')) and
                    apk_zip.getinfo(f).file_size < self.processing_limits['max_file_size_mb'] * 1024 * 1024)
            ]
            
            # Limit number of resource files for large APKs
            if self.extraction_context.is_large_apk:
                resource_files = resource_files[:self.processing_limits['max_resource_files']]
            
            for resource_file in resource_files:
                try:
                    # Read resource file
                    resource_data = apk_zip.read(resource_file)
                    
                    if resource_file.endswith('.xml'):
                        resource_text = self._extract_strings_from_binary(resource_data)
                    else:
                        resource_text = resource_data.decode('utf-8', errors='ignore')
                    
                    # Extract patterns
                    self._extract_patterns_from_text(
                        resource_text,
                        resource_file,
                        ExtractionMethod.RESOURCE_ANALYSIS
                    )
                    
                    self.stats['resource_files_processed'] += 1
                    
                except Exception as e:
                    logger.warning(f"Error processing resource file {resource_file}: {e}")
                    continue
            
            self.stats['total_files_processed'] += len(resource_files)
            logger.debug(f"Processed {len(resource_files)} resource files")
            
        except Exception as e:
            logger.error(f"Error extracting from resources: {e}")
            self.stats['processing_errors'] += 1
    
    def _extract_from_dex_files(self, apk_zip: zipfile.ZipFile) -> None:
        """Extract endpoints from DEX files."""
        try:
            logger.debug("Extracting from DEX files")
            
            # Get DEX files
            dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]
            
            # Limit DEX file processing for large APKs
            if self.extraction_context.is_large_apk:
                dex_files = dex_files[:self.processing_limits['max_dex_files']]
            
            for dex_file in dex_files:
                try:
                    # Read DEX file
                    dex_data = apk_zip.read(dex_file)
                    
                    # Extract strings from DEX binary
                    max_strings = (self.processing_limits['max_strings_per_file'] 
                                 if self.extraction_context.is_large_apk else None)
                    
                    dex_strings = self._extract_strings_from_binary(dex_data, max_strings)
                    
                    # Extract patterns from DEX strings
                    self._extract_patterns_from_text(
                        dex_strings,
                        dex_file,
                        ExtractionMethod.DEX_ANALYSIS
                    )
                    
                    self.stats['dex_files_processed'] += 1
                    
                except Exception as e:
                    logger.warning(f"Error processing DEX file {dex_file}: {e}")
                    continue
            
            self.stats['total_files_processed'] += len(dex_files)
            logger.debug(f"Processed {len(dex_files)} DEX files")
            
        except Exception as e:
            logger.error(f"Error extracting from DEX files: {e}")
            self.stats['processing_errors'] += 1
    
    def _extract_from_configs(self, apk_zip: zipfile.ZipFile) -> None:
        """Extract endpoints from configuration files."""
        try:
            logger.debug("Extracting from configuration files")
            
            # Look for configuration files
            config_patterns = ['.json', '.yaml', '.yml', '.properties', '.conf', '.cfg']
            config_files = [
                f for f in apk_zip.namelist()
                if any(f.endswith(pattern) for pattern in config_patterns) and
                apk_zip.getinfo(f).file_size < self.processing_limits['max_file_size_mb'] * 1024 * 1024
            ]
            
            for config_file in config_files:
                try:
                    # Read configuration file
                    config_data = apk_zip.read(config_file)
                    config_text = config_data.decode('utf-8', errors='ignore')
                    
                    # Special handling for JSON files
                    if config_file.endswith('.json'):
                        self._extract_from_json(config_text, config_file)
                    else:
                        # Extract patterns from other config files
                        self._extract_patterns_from_text(
                            config_text,
                            config_file,
                            ExtractionMethod.CONFIG_ANALYSIS
                        )
                    
                except Exception as e:
                    logger.warning(f"Error processing config file {config_file}: {e}")
                    continue
            
            self.stats['total_files_processed'] += len(config_files)
            logger.debug(f"Processed {len(config_files)} configuration files")
            
        except Exception as e:
            logger.error(f"Error extracting from configuration files: {e}")
            self.stats['processing_errors'] += 1
    
    def _extract_from_native_libs(self, apk_zip: zipfile.ZipFile) -> None:
        """Extract endpoints from native libraries."""
        try:
            logger.debug("Extracting from native libraries")
            
            # Get native library files
            native_libs = [
                f for f in apk_zip.namelist()
                if f.startswith('lib/') and f.endswith('.so')
            ]
            
            # Limit native library processing
            if self.extraction_context.is_large_apk:
                native_libs = native_libs[:self.processing_limits['max_native_libs']]
            
            for native_lib in native_libs:
                try:
                    # Read native library
                    lib_data = apk_zip.read(native_lib)
                    
                    # Limit binary scan size for performance
                    max_scan_size = self.processing_limits.get('max_binary_scan_size', 1048576)
                    if len(lib_data) > max_scan_size:
                        lib_data = lib_data[:max_scan_size]
                    
                    # Extract strings from binary
                    lib_strings = self._extract_strings_from_binary(lib_data)
                    
                    # Extract patterns from library strings
                    self._extract_patterns_from_text(
                        lib_strings,
                        native_lib,
                        ExtractionMethod.NATIVE_LIB_ANALYSIS
                    )
                    
                    self.stats['native_libs_processed'] += 1
                    
                except Exception as e:
                    logger.warning(f"Error processing native library {native_lib}: {e}")
                    continue
            
            self.stats['total_files_processed'] += len(native_libs)
            logger.debug(f"Processed {len(native_libs)} native libraries")
            
        except Exception as e:
            logger.error(f"Error extracting from native libraries: {e}")
            self.stats['processing_errors'] += 1
    
    def _extract_from_certificates(self, apk_zip: zipfile.ZipFile) -> None:
        """Extract endpoints from certificates."""
        try:
            logger.debug("Extracting from certificates")
            
            # Look for certificate files
            cert_files = [
                f for f in apk_zip.namelist()
                if (f.startswith('META-INF/') and 
                    (f.endswith('.RSA') or f.endswith('.DSA') or f.endswith('.EC')))
            ]
            
            for cert_file in cert_files:
                try:
                    # Read certificate file
                    cert_data = apk_zip.read(cert_file)
                    
                    # Extract strings from certificate binary
                    cert_strings = self._extract_strings_from_binary(cert_data)
                    
                    # Extract patterns from certificate strings
                    self._extract_patterns_from_text(
                        cert_strings,
                        cert_file,
                        ExtractionMethod.CERTIFICATE_ANALYSIS
                    )
                    
                    self.stats['certificates_processed'] += 1
                    
                except Exception as e:
                    logger.warning(f"Error processing certificate {cert_file}: {e}")
                    continue
            
            self.stats['total_files_processed'] += len(cert_files)
            logger.debug(f"Processed {len(cert_files)} certificates")
            
        except Exception as e:
            logger.error(f"Error extracting from certificates: {e}")
            self.stats['processing_errors'] += 1
    
    def _extract_patterns_from_text(self, text: str, file_path: str, 
                                  extraction_method: ExtractionMethod) -> None:
        """Extract URL patterns from text content."""
        try:
            # Use pattern analyzer to find matches
            pattern_matches = self.pattern_analyzer.analyze_text(text, file_path)
            
            for match in pattern_matches:
                # Skip if identified as noise
                if self.noise_filter.is_framework_noise(match.matched_text, file_path):
                    self.stats['noise_filtered'] += 1
                    continue
                
                # Categorize and store finding
                endpoint_type = self._categorize_finding(match.matched_text)
                if endpoint_type:
                    # Add to appropriate category
                    category_name = self._get_category_name(endpoint_type)
                    if category_name in self.raw_findings:
                        self.raw_findings[category_name].add(match.matched_text)
                    
                    # Create detailed finding
                    finding = EndpointFinding(
                        value=match.matched_text,
                        endpoint_type=endpoint_type,
                        extraction_method=extraction_method,
                        source_file=file_path,
                        risk_level=self._assess_risk_level(match.matched_text, endpoint_type),
                        protocol=self._determine_protocol(match.matched_text),
                        domain_category=self._categorize_domain(match.matched_text),
                        context=match.context_before + match.context_after
                    )
                    
                    # Calculate confidence
                    evidence = {
                        'pattern_type': match.pattern_name,
                        'validation_methods': ['syntax', 'format'],
                        'noise_filtered': True,
                        'passed_framework_check': True
                    }
                    finding.confidence = self.confidence_calculator.calculate_finding_confidence(
                        finding, evidence
                    )
                    
                    self.detailed_findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error extracting patterns from text: {e}")
            self.stats['processing_errors'] += 1
    
    def _extract_from_json(self, json_content: str, file_path: str) -> None:
        """Extract endpoints from JSON content."""
        try:
            data = json.loads(json_content)
            self._extract_from_json_recursive(data, file_path)
        except Exception as e:
            logger.warning(f"Error parsing JSON in {file_path}: {e}")
            # Fall back to text extraction
            self._extract_patterns_from_text(
                json_content, file_path, ExtractionMethod.JSON_ANALYSIS
            )
    
    def _extract_from_json_recursive(self, obj: Any, file_path: str) -> None:
        """Recursively extract endpoints from JSON object."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    self._extract_patterns_from_text(
                        value, file_path, ExtractionMethod.JSON_ANALYSIS
                    )
                else:
                    self._extract_from_json_recursive(value, file_path)
        elif isinstance(obj, list):
            for item in obj:
                self._extract_from_json_recursive(item, file_path)
        elif isinstance(obj, str):
            self._extract_patterns_from_text(
                obj, file_path, ExtractionMethod.JSON_ANALYSIS
            )
    
    def _extract_strings_from_binary(self, binary_data: bytes, 
                                   max_strings: Optional[int] = None) -> str:
        """Extract readable strings from binary data."""
        try:
            # Extract ASCII strings (4+ characters)
            ascii_pattern = re.compile(b'[\x20-\x7E]{4,}')
            ascii_strings = ascii_pattern.findall(binary_data)
            
            # Extract UTF-8 strings
            utf8_strings = []
            try:
                decoded = binary_data.decode('utf-8', errors='ignore')
                utf8_strings = [decoded]
            except:
                pass
            
            # Combine all strings
            all_strings = []
            for s in ascii_strings:
                try:
                    all_strings.append(s.decode('ascii'))
                except:
                    continue
            
            all_strings.extend(utf8_strings)
            
            # Limit number of strings if specified
            if max_strings and len(all_strings) > max_strings:
                all_strings = all_strings[:max_strings]
            
            return '\n'.join(all_strings)
            
        except Exception as e:
            logger.error(f"Error extracting strings from binary: {e}")
            return ""
    
    def _categorize_finding(self, text: str) -> Optional[EndpointType]:
        """Categorize a finding by endpoint type."""
        text_lower = text.lower()
        
        # Check for secrets first (highest priority)
        if self._is_potential_secret(text):
            return EndpointType.SECRET
        
        # Check for API endpoints
        if ('/api/' in text_lower or '/rest/' in text_lower or 
            '/service/' in text_lower or '/graphql' in text_lower):
            return EndpointType.API_ENDPOINT
        
        # Check for URLs
        if any(text.startswith(protocol) for protocol in 
               ['http://', 'https://', 'ftp://', 'ws://', 'wss://']):
            return EndpointType.URL
        
        # Check for custom scheme URLs
        if '://' in text and not text.startswith(('http', 'https', 'ftp')):
            return EndpointType.DEEP_LINK
        
        # Check for file URLs
        if text.startswith('file://'):
            return EndpointType.FILE_URL
        
        # Check for IP addresses
        if self._is_valid_ip(text):
            return EndpointType.IP_ADDRESS
        
        # Check for domains
        if self._is_valid_domain(text):
            return EndpointType.DOMAIN
        
        return None
    
    def _get_category_name(self, endpoint_type: EndpointType) -> str:
        """Get category name for endpoint type."""
        type_to_category = {
            EndpointType.URL: 'urls',
            EndpointType.IP_ADDRESS: 'ips',
            EndpointType.DOMAIN: 'domains',
            EndpointType.API_ENDPOINT: 'api_endpoints',
            EndpointType.DEEP_LINK: 'deep_links',
            EndpointType.FILE_URL: 'file_urls',
            EndpointType.CERTIFICATE: 'certificates',
            EndpointType.SECRET: 'secrets'
        }
        return type_to_category.get(endpoint_type, 'urls')
    
    def _assess_risk_level(self, text: str, endpoint_type: EndpointType) -> SecurityRisk:
        """Assess security risk level for finding."""
        # High priority risks
        if endpoint_type == EndpointType.SECRET:
            return SecurityRisk.CRITICAL
        
        if text.startswith('http://'):  # Cleartext HTTP
            return SecurityRisk.HIGH
        
        if endpoint_type == EndpointType.API_ENDPOINT:
            return SecurityRisk.HIGH
        
        if endpoint_type == EndpointType.IP_ADDRESS:
            return SecurityRisk.MEDIUM
        
        # Check for development/test indicators
        if any(keyword in text.lower() for keyword in 
               ['test', 'dev', 'debug', 'staging', 'localhost']):
            return SecurityRisk.MEDIUM
        
        return SecurityRisk.LOW
    
    def _determine_protocol(self, text: str) -> Optional[ProtocolType]:
        """Determine protocol type from text."""
        if text.startswith('https://'):
            return ProtocolType.HTTPS
        elif text.startswith('http://'):
            return ProtocolType.HTTP
        elif text.startswith('ftp://'):
            return ProtocolType.FTP
        elif text.startswith('wss://'):
            return ProtocolType.WEBSOCKET_SECURE
        elif text.startswith('ws://'):
            return ProtocolType.WEBSOCKET
        elif '://' in text:
            return ProtocolType.CUSTOM
        
        return None
    
    def _categorize_domain(self, text: str) -> Optional[DomainCategory]:
        """Categorize domain by type."""
        text_lower = text.lower()
        
        if any(keyword in text_lower for keyword in ['localhost', '127.0.0.1']):
            return DomainCategory.LOCALHOST
        elif any(keyword in text_lower for keyword in ['test', 'testing']):
            return DomainCategory.TESTING
        elif any(keyword in text_lower for keyword in ['dev', 'development']):
            return DomainCategory.DEVELOPMENT
        elif any(keyword in text_lower for keyword in ['staging', 'stage']):
            return DomainCategory.STAGING
        elif any(keyword in text_lower for keyword in ['debug', 'temp', 'admin']):
            return DomainCategory.SUSPICIOUS
        
        return DomainCategory.PRODUCTION
    
    def _is_potential_secret(self, text: str) -> bool:
        """Check if text might be a secret or credential."""
        secret_patterns = [
            r'(?i)(password|passwd|pwd|secret|key|token|auth)\s*[=:]\s*[\'"]?[a-zA-Z0-9+/=]{8,}',
            r'(?i)(api[_-]?key|access[_-]?token|secret[_-]?key)\s*[=:]\s*[\'"]?[a-zA-Z0-9+/=]{16,}'
        ]
        
        return any(re.search(pattern, text) for pattern in secret_patterns)
    
    def _is_valid_ip(self, text: str) -> bool:
        """Check if text is a valid IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(text)
            return True
        except:
            return False
    
    def _is_valid_domain(self, text: str) -> bool:
        """Check if text is a valid domain name."""
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        return bool(domain_pattern.match(text)) and '.' in text
    
    def _apply_noise_filtering(self) -> Dict[str, Set[str]]:
        """Apply final noise filtering to all findings."""
        filtered_results = {}
        
        for category, findings in self.raw_findings.items():
            filtered_findings = set()
            for finding in findings:
                if not self.noise_filter.is_framework_noise(finding):
                    filtered_findings.add(finding)
                else:
                    self.stats['noise_filtered'] += 1
            
            filtered_results[category] = filtered_findings
        
        return filtered_results 