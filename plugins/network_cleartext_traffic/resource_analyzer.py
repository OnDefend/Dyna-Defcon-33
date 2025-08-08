#!/usr/bin/env python3
"""
Network Cleartext Traffic Analyzer - Resource Analyzer

This module provides comprehensive analysis of application resources and code files
to detect HTTP URLs and cleartext traffic patterns.

Features:
- HTTP URL detection in code and resource files
- Pattern-based URL classification and risk assessment
- Domain analysis and categorization
- Hardcoded URL identification
- Configuration file analysis
- Performance-optimized file scanning

Classes:
    ResourceAnalyzer: Main resource and code analysis engine
"""

import logging
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Pattern
from datetime import datetime

from .data_structures import (
    ResourceAnalysisResult, HttpUrlDetection, HttpUrlType, RiskLevel,
    NetworkSecurityFinding, FindingType
)
from .confidence_calculator import NetworkCleartextConfidenceCalculator

class ResourceAnalyzer:
    """
    Resource analyzer for detecting HTTP URLs and cleartext traffic patterns.
    
    Scans application code, resources, and configuration files to identify
    hardcoded HTTP URLs and potential cleartext traffic vulnerabilities.
    """
    
    def __init__(self, confidence_calculator: NetworkCleartextConfidenceCalculator):
        """
        Initialize resource analyzer.
        
        Args:
            confidence_calculator: Confidence calculation engine
        """
        self.logger = logging.getLogger(__name__)
        self.confidence_calculator = confidence_calculator
        
        # Compiled HTTP URL patterns for efficient scanning
        self.http_patterns = self._compile_http_patterns()
        
        # File extensions to scan
        self.scan_extensions = {
            'code_files': {'.java', '.kt', '.scala', '.groovy'},
            'resource_files': {'.xml', '.json', '.properties', '.yml', '.yaml'},
            'config_files': {'.conf', '.config', '.ini', '.cfg'},
            'web_files': {'.html', '.htm', '.js', '.css'},
            'text_files': {'.txt', '.md', '.rst'}
        }
        
        # All scannable extensions
        self.all_extensions = set()
        for ext_set in self.scan_extensions.values():
            self.all_extensions.update(ext_set)
        
        # Domain classification patterns
        self.domain_classifiers = self._compile_domain_classifiers()
        
        # Processing limits
        self.max_files_to_scan = 10000
        self.max_file_size_mb = 50
        self.max_http_urls_per_file = 100
        self.scan_timeout_seconds = 300
    
    def analyze_resources_and_code(self, apk_path: Path) -> ResourceAnalysisResult:
        """
        Analyze resources and code files for HTTP URLs.
        
        Args:
            apk_path: Path to extracted APK directory
            
        Returns:
            ResourceAnalysisResult with detected HTTP URLs and analysis data
        """
        result = ResourceAnalysisResult()
        
        try:
            start_time = datetime.now()
            
            # Find files to scan
            files_to_scan = self._find_scannable_files(apk_path)
            
            if not files_to_scan:
                self.logger.info("No files found to scan for HTTP URLs")
                return result
            
            # Limit files to scan for performance
            if len(files_to_scan) > self.max_files_to_scan:
                self.logger.warning(
                    f"Too many files to scan ({len(files_to_scan)}), limiting to {self.max_files_to_scan}"
                )
                files_to_scan = files_to_scan[:self.max_files_to_scan]
            
            result.files_scanned = len(files_to_scan)
            
            # Scan files for HTTP URLs
            self._scan_files_for_http_urls(files_to_scan, result)
            
            # Analyze detected URLs
            self._analyze_detected_urls(result)
            
            # Analyze configuration files specifically
            self._analyze_config_files(apk_path, result)
            
            # Calculate scan statistics
            scan_duration = (datetime.now() - start_time).total_seconds()
            result.scan_statistics = {
                'scan_duration_seconds': scan_duration,
                'files_per_second': result.files_scanned / max(scan_duration, 1),
                'urls_per_file': len(result.http_urls_found) / max(result.files_scanned, 1),
                'unique_domains': len(result.get_unique_domains()),
                'high_risk_urls': len(result.get_high_risk_urls())
            }
            
            self.logger.info(
                f"Resource analysis completed: {result.files_scanned} files scanned, "
                f"{len(result.http_urls_found)} HTTP URLs found"
            )
            
        except Exception as e:
            self.logger.error(f"Error analyzing resources and code: {e}")
            result.analysis_errors.append(f"Analysis error: {e}")
        
        return result
    
    def _compile_http_patterns(self) -> List[Pattern[str]]:
        """Compile HTTP URL detection patterns"""
        patterns = [
            # Basic HTTP URLs
            re.compile(r'http://[^\s\'"<>]+', re.IGNORECASE),
            
            # Quoted HTTP URLs
            re.compile(r'"http://[^"]*"', re.IGNORECASE),
            re.compile(r"'http://[^']*'", re.IGNORECASE),
            
            # XML encoded HTTP URLs
            re.compile(r'&quot;http://[^&]*&quot;', re.IGNORECASE),
            
            # JSON format HTTP URLs
            re.compile(r'"url"\s*:\s*"http://[^"]*"', re.IGNORECASE),
            re.compile(r'"endpoint"\s*:\s*"http://[^"]*"', re.IGNORECASE),
            re.compile(r'"baseUrl"\s*:\s*"http://[^"]*"', re.IGNORECASE),
            
            # Code patterns
            re.compile(r'URL\s*\(\s*"http://[^"]*"', re.IGNORECASE),
            re.compile(r'HttpURLConnection\s*.*"http://[^"]*"', re.IGNORECASE),
            
            # Configuration patterns
            re.compile(r'url\s*=\s*http://[^\s]+', re.IGNORECASE),
            re.compile(r'endpoint\s*=\s*http://[^\s]+', re.IGNORECASE),
            
            # API endpoint patterns
            re.compile(r'http://[a-zA-Z0-9.-]+(/api|/v\d+|/rest)', re.IGNORECASE),
            
            # IP address patterns
            re.compile(r'http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE)
        ]
        
        return patterns
    
    def _compile_domain_classifiers(self) -> Dict[str, List[Pattern[str]]]:
        """Compile domain classification patterns"""
        return {
            'localhost': [
                re.compile(r'^(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.0\.2\.2)$', re.IGNORECASE)
            ],
            'test_domains': [
                re.compile(r'^(test\.com|example\.com|localhost\.com)$', re.IGNORECASE),
                re.compile(r'\.test$', re.IGNORECASE),
                re.compile(r'test\d*\.', re.IGNORECASE)
            ],
            'analytics': [
                re.compile(r'google-analytics\.com$', re.IGNORECASE),
                re.compile(r'googletagmanager\.com$', re.IGNORECASE),
                re.compile(r'doubleclick\.net$', re.IGNORECASE),
                re.compile(r'firebase\.com$', re.IGNORECASE),
                re.compile(r'crashlytics\.com$', re.IGNORECASE)
            ],
            'advertisement': [
                re.compile(r'admob\.com$', re.IGNORECASE),
                re.compile(r'adsystem\.com$', re.IGNORECASE),
                re.compile(r'googlesyndication\.com$', re.IGNORECASE),
                re.compile(r'amazon-adsystem\.com$', re.IGNORECASE)
            ],
            'social_apis': [
                re.compile(r'api\.facebook\.com$', re.IGNORECASE),
                re.compile(r'api\.twitter\.com$', re.IGNORECASE),
                re.compile(r'api\.instagram\.com$', re.IGNORECASE),
                re.compile(r'graph\.facebook\.com$', re.IGNORECASE)
            ],
            'cdn': [
                re.compile(r'\.cloudfront\.net$', re.IGNORECASE),
                re.compile(r'\.amazonaws\.com$', re.IGNORECASE),
                re.compile(r'\.azureedge\.net$', re.IGNORECASE),
                re.compile(r'\.fastly\.com$', re.IGNORECASE)
            ]
        }
    
    def _find_scannable_files(self, apk_path: Path) -> List[Path]:
        """Find all files that should be scanned for HTTP URLs"""
        files_to_scan = []
        
        try:
            # Scan recursively for files with target extensions
            for file_path in apk_path.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in self.all_extensions:
                    # Check file size
                    try:
                        file_size_mb = file_path.stat().st_size / (1024 * 1024)
                        if file_size_mb <= self.max_file_size_mb:
                            files_to_scan.append(file_path)
                        else:
                            self.logger.debug(f"Skipping large file: {file_path} ({file_size_mb:.1f}MB)")
                    except Exception:
                        # If we can't get file size, skip it
                        continue
            
            # Sort files for consistent processing order
            files_to_scan.sort()
            
        except Exception as e:
            self.logger.error(f"Error finding scannable files: {e}")
        
        return files_to_scan
    
    def _scan_files_for_http_urls(self, files_to_scan: List[Path], result: ResourceAnalysisResult):
        """Scan files for HTTP URLs using unified performance optimization framework"""
        try:
            # Use unified performance optimization framework
            from core.performance_optimizer import ParallelProcessor
            
            # Create parallel processor with unified framework
            max_workers = min(5, len(files_to_scan))
            parallel_processor = ParallelProcessor(max_workers=max_workers)
            
            # Process files using unified parallel framework
            results = parallel_processor.process_parallel(
                items=files_to_scan,
                processor_func=self._scan_single_file,
                timeout=self.scan_timeout_seconds
            )
            
            # Collect and process results
            for file_urls in results:
                if file_urls:
                    result.http_urls_found.extend(file_urls)
                    
                    # Limit URLs per analysis to prevent memory issues
                    if len(result.http_urls_found) > 1000:  # Reasonable limit
                        self.logger.warning(f"URL limit reached (1000), stopping scan")
                        break
            
            self.logger.info(f"Unified parallel file scanning completed: {len(files_to_scan)} files, "
                           f"{len(result.http_urls_found)} URLs found")
            
        except Exception as e:
            self.logger.warning(f"Unified performance framework failed, using fallback: {e}")
            # Fallback to original ThreadPoolExecutor implementation
            self._scan_files_parallel_fallback(files_to_scan, result)

    def _scan_files_parallel_fallback(self, files_to_scan, result):
        """Fallback file scanning method using ThreadPoolExecutor."""
        try:
            # Use thread pool for parallel scanning
            max_workers = min(5, len(files_to_scan))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit scanning tasks
                future_to_file = {
                    executor.submit(self._scan_single_file, file_path): file_path
                    for file_path in files_to_scan
                }
                
                # Collect results
                for future in as_completed(future_to_file, timeout=self.scan_timeout_seconds):
                    file_path = future_to_file[future]
                    
                    try:
                        file_urls = future.result()
                        result.http_urls_found.extend(file_urls)
                        
                        # Limit URLs per analysis to prevent memory issues
                        if len(result.http_urls_found) > 1000:  # Reasonable limit
                            self.logger.warning(f"URL limit reached (1000), stopping scan")
                            break
                            
                    except Exception as e:
                        self.logger.debug(f"Error scanning file {file_path}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Fallback parallel file scanning failed: {e}")
            # Sequential fallback
            for file_path in files_to_scan:
                try:
                    file_urls = self._scan_single_file(file_path)
                    if file_urls:
                        result.http_urls_found.extend(file_urls)
                        
                        if len(result.http_urls_found) > 1000:
                            break
                except Exception as e:
                    self.logger.debug(f"Error scanning file {file_path}: {e}")
    
    def _scan_single_file(self, file_path: Path) -> List[HttpUrlDetection]:
        """Scan a single file for HTTP URLs"""
        urls_found = []
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Track line numbers for better reporting
            lines = content.split('\n')
            
            # Apply each HTTP pattern
            for pattern in self.http_patterns:
                matches = pattern.finditer(content)
                
                for match in matches:
                    url = match.group().strip('\'"')
                    
                    # Clean up URL (remove quotes, etc.)
                    url = self._clean_url(url)
                    
                    if url and self._is_valid_http_url(url):
                        # Find line number
                        line_number = self._find_line_number(content, match.start(), lines)
                        
                        # Extract context
                        context = self._extract_context(content, match.start(), match.end())
                        
                        # Create URL detection
                        detection = HttpUrlDetection(
                            url=url,
                            file_path=str(file_path),
                            line_number=line_number,
                            context=context,
                            url_type=self._classify_url_type(url, str(file_path), context),
                            risk_level=self._assess_url_risk(url, str(file_path)),
                            is_hardcoded=True
                        )
                        
                        urls_found.append(detection)
                        
                        # Limit URLs per file
                        if len(urls_found) >= self.max_http_urls_per_file:
                            break
                
                # Stop if we've found too many URLs
                if len(urls_found) >= self.max_http_urls_per_file:
                    break
        
        except Exception as e:
            self.logger.debug(f"Error scanning file {file_path}: {e}")
        
        return urls_found
    
    def _clean_url(self, url: str) -> str:
        """Clean and normalize URL"""
        # Remove common quote marks and delimiters
        url = url.strip('\'"')
        
        # Remove XML encoding
        url = url.replace('&quot;', '"').replace('&amp;', '&')
        
        # Remove trailing punctuation that's not part of URL
        while url and url[-1] in '.,;!?':
            url = url[:-1]
        
        return url
    
    def _is_valid_http_url(self, url: str) -> bool:
        """Check if URL is a valid HTTP URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            return (
                parsed.scheme == 'http' and
                parsed.netloc and
                len(url) > 10 and  # Minimum reasonable URL length
                '.' in parsed.netloc  # Domain should contain dot
            )
        except Exception:
            return False
    
    def _find_line_number(self, content: str, start_pos: int, lines: List[str]) -> Optional[int]:
        """Find line number for a position in the content"""
        try:
            # Count newlines up to the position
            line_number = content[:start_pos].count('\n') + 1
            return line_number
        except Exception:
            return None
    
    def _extract_context(self, content: str, start_pos: int, end_pos: int, context_size: int = 50) -> str:
        """Extract context around the URL match"""
        try:
            # Get context before and after
            context_start = max(0, start_pos - context_size)
            context_end = min(len(content), end_pos + context_size)
            
            context = content[context_start:context_end]
            
            # Clean up context (remove newlines, extra spaces)
            context = ' '.join(context.split())
            
            return context
        except Exception:
            return ""
    
    def _classify_url_type(self, url: str, file_path: str, context: str) -> HttpUrlType:
        """Classify URL type based on URL, file path, and context"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for localhost/test domains
            if self._matches_domain_patterns(domain, 'localhost'):
                return HttpUrlType.TEST_URL
            
            if self._matches_domain_patterns(domain, 'test_domains'):
                return HttpUrlType.TEST_URL
            
            # Check for API endpoints
            if any(indicator in path for indicator in ['/api', '/v1', '/v2', '/rest', '/service']):
                return HttpUrlType.HARDCODED_API
            
            # Check for analytics/tracking
            if self._matches_domain_patterns(domain, 'analytics'):
                return HttpUrlType.ANALYTICS_URL
            
            # Check for advertisements
            if self._matches_domain_patterns(domain, 'advertisement'):
                return HttpUrlType.ADVERTISEMENT_URL
            
            # Check for social media APIs
            if self._matches_domain_patterns(domain, 'social_apis'):
                return HttpUrlType.EXTERNAL_SERVICE
            
            # Check context for configuration
            if any(keyword in context.lower() for keyword in ['config', 'endpoint', 'base_url', 'server']):
                return HttpUrlType.CONFIG_URL
            
            # Check file path for test indication
            if any(indicator in file_path.lower() for indicator in ['test', 'debug', 'sample']):
                return HttpUrlType.TEST_URL
            
            # Default classification
            return HttpUrlType.RESOURCE_URL
            
        except Exception:
            return HttpUrlType.UNKNOWN
    
    def _assess_url_risk(self, url: str, file_path: str) -> RiskLevel:
        """Assess risk level of HTTP URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # High risk: API endpoints
            if any(indicator in path for indicator in ['/api', '/service', '/auth', '/login']):
                return RiskLevel.HIGH
            
            # High risk: IP addresses
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                return RiskLevel.HIGH
            
            # Medium risk: External services
            if self._matches_domain_patterns(domain, 'social_apis'):
                return RiskLevel.MEDIUM
            
            # Low risk: Test/localhost domains
            if self._matches_domain_patterns(domain, ['localhost', 'test_domains']):
                return RiskLevel.LOW
            
            # Medium risk: Analytics/ads (privacy concern)
            if self._matches_domain_patterns(domain, ['analytics', 'advertisement']):
                return RiskLevel.MEDIUM
            
            # Check file context
            if any(indicator in file_path.lower() for indicator in ['test', 'debug', 'sample']):
                return RiskLevel.LOW
            
            # Default risk level
            return RiskLevel.MEDIUM
            
        except Exception:
            return RiskLevel.MEDIUM
    
    def _matches_domain_patterns(self, domain: str, pattern_groups: any) -> bool:
        """Check if domain matches any pattern in the specified groups"""
        if isinstance(pattern_groups, str):
            pattern_groups = [pattern_groups]
        
        for group_name in pattern_groups:
            patterns = self.domain_classifiers.get(group_name, [])
            for pattern in patterns:
                if pattern.search(domain):
                    return True
        
        return False
    
    def _analyze_detected_urls(self, result: ResourceAnalysisResult):
        """Analyze and categorize detected URLs"""
        if not result.http_urls_found:
            return
        
        # Group URLs by domain
        domain_groups = {}
        for detection in result.http_urls_found:
            domain = detection.domain
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(detection)
        
        # Analyze patterns
        suspicious_patterns = []
        
        # Check for multiple URLs from same domain
        for domain, detections in domain_groups.items():
            if len(detections) > 5:
                suspicious_patterns.append({
                    'type': 'multiple_urls_same_domain',
                    'domain': domain,
                    'count': len(detections),
                    'risk_level': 'MEDIUM',
                    'description': f'Multiple HTTP URLs found for domain {domain}'
                })
        
        # Check for high-risk URL patterns
        high_risk_urls = result.get_high_risk_urls()
        if high_risk_urls:
            suspicious_patterns.append({
                'type': 'high_risk_http_urls',
                'count': len(high_risk_urls),
                'risk_level': 'HIGH',
                'description': f'{len(high_risk_urls)} high-risk HTTP URLs detected'
            })
        
        result.suspicious_patterns = suspicious_patterns
    
    def _analyze_config_files(self, apk_path: Path, result: ResourceAnalysisResult):
        """Analyze configuration files specifically for HTTP URLs"""
        config_dirs = [
            'assets',
            'res/raw',
            'res/values',
            'META-INF'
        ]
        
        config_files_analyzed = []
        
        for config_dir in config_dirs:
            dir_path = apk_path / config_dir
            if dir_path.exists():
                for config_file in dir_path.rglob('*'):
                    if config_file.is_file():
                        file_ext = config_file.suffix.lower()
                        if file_ext in {'.properties', '.xml', '.json', '.yml', '.yaml', '.conf', '.config'}:
                            config_files_analyzed.append(str(config_file))
        
        result.config_files_analyzed = config_files_analyzed
    
    def generate_security_findings(self, result: ResourceAnalysisResult) -> List[NetworkSecurityFinding]:
        """
        Generate NetworkSecurityFinding objects from resource analysis.
        
        Args:
            result: Resource analysis result
            
        Returns:
            List of NetworkSecurityFinding objects with calculated confidence
        """
        security_findings = []
        
        if not result.http_urls_found:
            return security_findings
        
        try:
            # Group findings by type
            findings_by_type = {}
            
            for detection in result.http_urls_found:
                finding_key = f"{detection.url_type.value}_{detection.risk_level.value}"
                
                if finding_key not in findings_by_type:
                    findings_by_type[finding_key] = {
                        'detections': [],
                        'url_type': detection.url_type,
                        'risk_level': detection.risk_level
                    }
                
                findings_by_type[finding_key]['detections'].append(detection)
            
            # Create findings for each type
            for finding_key, finding_data in findings_by_type.items():
                detections = finding_data['detections']
                url_type = finding_data['url_type']
                risk_level = finding_data['risk_level']
                
                # Limit evidence to prevent overwhelming output
                evidence = []
                for detection in detections[:10]:  # Max 10 examples
                    evidence.append(f"{detection.url} (in {Path(detection.file_path).name})")
                
                if len(detections) > 10:
                    evidence.append(f"... and {len(detections) - 10} more HTTP URLs")
                
                # Create security finding
                finding = NetworkSecurityFinding(
                    finding_type=FindingType.HTTP_URL_FOUND,
                    severity=risk_level,
                    title=f"HTTP URLs Found - {url_type.value.replace('_', ' ').title()}",
                    description=f"Found {len(detections)} HTTP URLs of type {url_type.value}",
                    location="Application Resources",
                    evidence=evidence,
                    remediation=self._get_url_type_remediation(url_type),
                    masvs_control="MASVS-NETWORK-1",
                    mastg_reference="MASTG-TEST-0024",
                    detection_method="resource_scan"
                )
                
                # Calculate confidence using first detection as representative
                representative_detection = detections[0]
                finding.confidence = self.confidence_calculator.calculate_http_url_confidence(
                    representative_detection,
                    context={
                        'file_type': 'resource',
                        'analysis_source': 'resource_analyzer',
                        'url_count': len(detections)
                    }
                )
                
                security_findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error generating resource security findings: {e}")
        
        return security_findings
    
    def _get_url_type_remediation(self, url_type: HttpUrlType) -> List[str]:
        """Get remediation recommendations for URL type"""
        remediation_map = {
            HttpUrlType.HARDCODED_API: [
                "Replace HTTP API endpoints with HTTPS equivalents",
                "Implement certificate pinning for API connections",
                "Store API endpoints in secure configuration"
            ],
            HttpUrlType.CONFIG_URL: [
                "Use HTTPS for configuration endpoints",
                "Implement secure configuration loading",
                "Validate server certificates"
            ],
            HttpUrlType.TEST_URL: [
                "Remove test URLs from production builds",
                "Use build variants for test configurations",
                "Ensure test endpoints are not accessible in production"
            ],
            HttpUrlType.EXTERNAL_SERVICE: [
                "Use HTTPS for external service communications",
                "Implement proper certificate validation",
                "Consider service-specific security requirements"
            ],
            HttpUrlType.ANALYTICS_URL: [
                "Use HTTPS for analytics services",
                "Review privacy implications of HTTP analytics",
                "Consider user consent for data collection"
            ]
        }
        
        return remediation_map.get(url_type, [
            "Replace HTTP URLs with HTTPS equivalents",
            "Implement certificate validation",
            "Review necessity of external HTTP connections"
        ]) 