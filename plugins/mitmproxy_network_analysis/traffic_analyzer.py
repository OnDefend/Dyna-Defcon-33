#!/usr/bin/env python3
"""
Network Traffic Analyzer Module

This module provides comprehensive analysis of captured network traffic including:
- Traffic pattern analysis and classification
- Insecure communication detection
- Security issue identification
- Traffic summary generation
- Pattern matching with confidence scoring

Features:
- Multi-threaded traffic analysis
- Comprehensive security pattern detection
- confidence calculation integration
- Traffic classification and risk assessment
- Evidence-based security scoring

"""

import logging
import re
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

from .data_structures import (
    NetworkFlow, SecurityIssue, TrafficSummary, TrafficType, 
    SecurityLevel, VulnerabilityType
)
from .confidence_calculator import NetworkConfidenceCalculator, NetworkConfidenceEvidence
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

logger = logging.getLogger(__name__)

class NetworkTrafficAnalyzer:
    """
    Comprehensive network traffic analyzer with security assessment.
    
    Analyzes captured network traffic for security vulnerabilities,
    insecure communications, and generates detailed security reports
    with professional confidence scoring.
    """
    
    def __init__(self, config: Dict[str, Any], confidence_calculator: NetworkConfidenceCalculator):
        """
        Initialize traffic analyzer.
        
        Args:
            config: Network patterns configuration
            confidence_calculator: confidence calculator
        """
        self.config = config
        self.confidence_calculator = confidence_calculator
        self.logger = logging.getLogger(__name__)
        
        # Load security patterns from configuration
        self.security_patterns = self._load_security_patterns()
        
        # Analysis results storage
        self.flows: List[NetworkFlow] = []
        self.security_issues: List[SecurityIssue] = []
        self.traffic_summary: Optional[TrafficSummary] = None
        
        self.logger.debug("Network traffic analyzer initialized")
    
    def _load_security_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load security patterns from configuration."""
        patterns = {}
        
        if 'network_security_patterns' in self.config:
            for category, pattern_list in self.config['network_security_patterns'].items():
                patterns[category] = pattern_list
        
        # Add default patterns if not in config
        if not patterns:
            patterns = self._get_default_security_patterns()
        
        self.logger.debug(f"Loaded {sum(len(p) for p in patterns.values())} security patterns")
        return patterns
    
    def _get_default_security_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get default security patterns if configuration not available."""
        return {
            'http_urls': [
                {
                    'pattern': r'http://[^\s"\'<>]+',
                    'description': 'HTTP URLs in traffic',
                    'severity': 'HIGH',
                    'confidence': 0.95,
                    'cwe': 'CWE-319',
                    'masvs_control': 'MSTG-NETWORK-01'
                }
            ],
            'sensitive_data': [
                {
                    'pattern': r'[aA][pP][iI][_-]?[kK][eE][yY]["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})',
                    'description': 'API keys in traffic',
                    'severity': 'CRITICAL',
                    'confidence': 0.88,
                    'cwe': 'CWE-200',
                    'masvs_control': 'MSTG-NETWORK-01'
                }
            ]
        }
    
    def analyze_traffic(self, flows_data: List[Dict[str, Any]]) -> Tuple[List[NetworkFlow], List[SecurityIssue], TrafficSummary]:
        """
        Perform comprehensive traffic analysis.
        
        Args:
            flows_data: Raw flow data from MITMProxy
            
        Returns:
            Tuple of (flows, security_issues, traffic_summary)
        """
        try:
            self.logger.info(f"Starting analysis of {len(flows_data)} network flows")
            
            # Convert raw data to NetworkFlow objects
            self.flows = self._convert_flows_data(flows_data)
            
            # Analyze traffic for security issues
            self.security_issues = self._analyze_security_issues()
            
            # Generate traffic summary
            self.traffic_summary = self._generate_traffic_summary()
            
            self.logger.info(f"Traffic analysis completed: {len(self.security_issues)} security issues found")
            return self.flows, self.security_issues, self.traffic_summary
            
        except Exception as e:
            self.logger.error(f"Error during traffic analysis: {e}")
            return [], [], TrafficSummary(0, 0, 0, 0, 0, 0, 0, 0.0, 0.0)
    
    def _convert_flows_data(self, flows_data: List[Dict[str, Any]]) -> List[NetworkFlow]:
        """Convert raw flow data to NetworkFlow objects."""
        flows = []
        
        for flow_data in flows_data:
            try:
                flow = NetworkFlow(
                    id=flow_data.get('id', ''),
                    method=flow_data.get('method', ''),
                    url=flow_data.get('url', ''),
                    host=flow_data.get('host', ''),
                    port=flow_data.get('port', 0),
                    scheme=flow_data.get('scheme', ''),
                    path=flow_data.get('path', ''),
                    timestamp=datetime.fromisoformat(flow_data.get('timestamp', datetime.now().isoformat())),
                    request_headers=flow_data.get('request_headers', {}),
                    response_headers=flow_data.get('response_headers', {}),
                    request_body=flow_data.get('request_body', ''),
                    response_body=flow_data.get('response_body', ''),
                    response_code=flow_data.get('response_code', 0),
                    response_size=flow_data.get('response_size', 0),
                    duration=flow_data.get('duration', 0.0)
                )
                flows.append(flow)
                
            except Exception as e:
                self.logger.warning(f"Failed to convert flow data: {e}")
                continue
        
        return flows
    
    def _analyze_security_issues(self) -> List[SecurityIssue]:
        """Analyze flows for security issues using unified performance optimization framework."""
        security_issues = []
        
        try:
            # Use unified performance optimization framework
            from core.performance_optimizer import ParallelProcessor
            from functools import partial
            
            # Create parallel processor with unified framework
            parallel_processor = ParallelProcessor(max_workers=4)
            
            # Process flows using unified parallel framework
            results = parallel_processor.process_parallel(
                items=self.flows,
                processor_func=self._analyze_flow_security,
                timeout=30  # 30 seconds per flow
            )
            
            # Flatten results and filter out None values
            for flow_issues in results:
                if flow_issues:
                    security_issues.extend(flow_issues)
            
            self.logger.info(f"Unified parallel security analysis completed: {len(self.flows)} flows, "
                           f"{len(security_issues)} security issues found")
            
        except Exception as e:
            self.logger.warning(f"Unified performance framework failed, using fallback: {e}")
            # Fallback to original ThreadPoolExecutor implementation
            security_issues = self._analyze_security_issues_fallback()
        
        # Deduplicate issues
        security_issues = self._deduplicate_security_issues(security_issues)
        
        return security_issues

    def _analyze_security_issues_fallback(self) -> List[SecurityIssue]:
        """Fallback security analysis method using ThreadPoolExecutor."""
        security_issues = []
        
        try:
            # Use thread pool for parallel analysis
            with ThreadPoolExecutor(max_workers=4) as executor:
                # Submit analysis tasks
                future_to_flow = {
                    executor.submit(self._analyze_flow_security, flow): flow 
                    for flow in self.flows
                }
                
                # Collect results
                for future in as_completed(future_to_flow):
                    flow = future_to_flow[future]
                    try:
                        flow_issues = future.result()
                        if flow_issues:
                            security_issues.extend(flow_issues)
                    except Exception as e:
                        self.logger.error(f"Error analyzing flow security: {e}")
        
        except Exception as e:
            self.logger.error(f"Parallel security analysis failed: {e}")
            # Sequential fallback
            for flow in self.flows:
                try:
                    flow_issues = self._analyze_flow_security(flow)
                    if flow_issues:
                        security_issues.extend(flow_issues)
                except Exception as e:
                    self.logger.error(f"Error analyzing flow security: {e}")
        
        return security_issues
    
    def _analyze_flow_security(self, flow: NetworkFlow) -> List[SecurityIssue]:
        """Analyze individual flow for security issues."""
        issues = []
        
        try:
            # Check for insecure HTTP usage
            issues.extend(self._check_insecure_http(flow))
            
            # Check for sensitive data exposure
            issues.extend(self._check_sensitive_data_exposure(flow))
            
            # Check for injection vulnerabilities
            issues.extend(self._check_injection_vulnerabilities(flow))
            
            # Check for authentication issues
            issues.extend(self._check_authentication_issues(flow))
            
            # Check for missing security headers
            issues.extend(self._check_security_headers(flow))
            
            return issues
            
        except Exception as e:
            self.logger.error(f"Error analyzing flow security: {e}")
            return []
    
    def _check_insecure_http(self, flow: NetworkFlow) -> List[SecurityIssue]:
        """Check for insecure HTTP communications."""
        issues = []
        
        if flow.scheme == 'http':
            # Calculate confidence based on evidence
            evidence = NetworkConfidenceEvidence()
            evidence.pattern_match_quality = 1.0  # Direct scheme match
            evidence.pattern_context_relevance = 1.0
            evidence.false_positive_likelihood = 0.0
            evidence.analysis_depth = 0.9
            evidence.traffic_capture_completeness = 0.9
            
            confidence = self.confidence_calculator.calculate_network_confidence(
                finding_type='http_urls',
                evidence=evidence,
                pattern_id='http_urls'
            )
            
            issue = SecurityIssue(
                issue_type=VulnerabilityType.INSECURE_HTTP.value,
                severity='HIGH',
                description=f'Insecure HTTP communication detected to {flow.host}',
                affected_urls=[flow.url],
                evidence=[f'HTTP request to {flow.url}'],
                confidence=confidence,
                impact='Data transmitted in cleartext can be intercepted',
                remediation='Use HTTPS instead of HTTP for all communications'
            )
            issues.append(issue)
        
        return issues
    
    def _check_sensitive_data_exposure(self, flow: NetworkFlow) -> List[SecurityIssue]:
        """Check for sensitive data exposure in traffic."""
        issues = []
        
        # Check URL parameters
        if '?' in flow.url:
            query_params = parse_qs(urlparse(flow.url).query)
            issues.extend(self._analyze_sensitive_data_in_params(flow, query_params))
        
        # Check request body
        if flow.request_body:
            issues.extend(self._analyze_sensitive_data_in_body(flow, flow.request_body, 'request'))
        
        # Check response body
        if flow.response_body:
            issues.extend(self._analyze_sensitive_data_in_body(flow, flow.response_body, 'response'))
        
        return issues
    
    def _analyze_sensitive_data_in_params(self, flow: NetworkFlow, params: Dict[str, List[str]]) -> List[SecurityIssue]:
        """Analyze URL parameters for sensitive data."""
        issues = []
        
        sensitive_patterns = self.security_patterns.get('sensitive_data', [])
        
        for pattern_info in sensitive_patterns:
            pattern = pattern_info['pattern']
            
            for param_name, param_values in params.items():
                for value in param_values:
                    if re.search(pattern, f"{param_name}={value}", re.IGNORECASE):
                        # Calculate professional confidence
                        evidence = NetworkConfidenceEvidence()
                        evidence.pattern_match_quality = 0.9
                        evidence.pattern_context_relevance = 0.8
                        evidence.false_positive_likelihood = 0.2
                        evidence.analysis_depth = 0.8
                        
                        confidence = self.confidence_calculator.calculate_network_confidence(
                            finding_type='sensitive_data',
                            evidence=evidence,
                            pattern_id='api_keys'
                        )
                        
                        issue = SecurityIssue(
                            issue_type=VulnerabilityType.DATA_EXPOSURE.value,
                            severity=pattern_info.get('severity', 'HIGH'),
                            description=f'Sensitive data in URL parameter: {pattern_info["description"]}',
                            affected_urls=[flow.url],
                            evidence=[f'Parameter {param_name} contains sensitive data'],
                            confidence=confidence,
                            impact='Sensitive data may be logged or exposed in URLs',
                            remediation='Move sensitive data to request body with proper encryption'
                        )
                        issues.append(issue)
        
        return issues
    
    def _analyze_sensitive_data_in_body(self, flow: NetworkFlow, body: str, location: str) -> List[SecurityIssue]:
        """Analyze request/response body for sensitive data."""
        issues = []
        
        sensitive_patterns = self.security_patterns.get('sensitive_data', [])
        
        for pattern_info in sensitive_patterns:
            pattern = pattern_info['pattern']
            
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                # Calculate professional confidence
                evidence = NetworkConfidenceEvidence()
                evidence.pattern_match_quality = 0.85
                evidence.pattern_context_relevance = 0.9 if location == 'request' else 0.8
                evidence.false_positive_likelihood = 0.15
                evidence.analysis_depth = 0.9
                
                confidence = self.confidence_calculator.calculate_network_confidence(
                    finding_type='sensitive_data',
                    evidence=evidence,
                    pattern_id='sensitive_data'
                )
                
                issue = SecurityIssue(
                    issue_type=VulnerabilityType.DATA_EXPOSURE.value,
                    severity=pattern_info.get('severity', 'HIGH'),
                    description=f'Sensitive data in {location}: {pattern_info["description"]}',
                    affected_urls=[flow.url],
                    evidence=[f'Found {len(matches)} instances in {location} body'],
                    confidence=confidence,
                    impact=f'Sensitive data exposed in {location} may be intercepted or logged',
                    remediation='Encrypt sensitive data before transmission'
                )
                issues.append(issue)
        
        return issues
    
    def _check_injection_vulnerabilities(self, flow: NetworkFlow) -> List[SecurityIssue]:
        """Check for injection vulnerability patterns."""
        issues = []
        
        injection_patterns = self.security_patterns.get('sql_injection', []) + self.security_patterns.get('xss_patterns', [])
        
        # Check request parameters and body
        check_locations = [
            ('url', flow.url),
            ('request_body', flow.request_body)
        ]
        
        for location, content in check_locations:
            if not content:
                continue
                
            for pattern_info in injection_patterns:
                pattern = pattern_info['pattern']
                
                if re.search(pattern, content, re.IGNORECASE):
                    # Calculate professional confidence
                    evidence = NetworkConfidenceEvidence()
                    evidence.pattern_match_quality = 0.75  # Injection patterns can have false positives
                    evidence.pattern_context_relevance = 0.8
                    evidence.false_positive_likelihood = 0.25
                    evidence.analysis_depth = 0.8
                    
                    confidence = self.confidence_calculator.calculate_network_confidence(
                        finding_type='injection_vulnerabilities',
                        evidence=evidence,
                        pattern_id='sql_injection'
                    )
                    
                    issue = SecurityIssue(
                        issue_type=VulnerabilityType.INJECTION_RISK.value,
                        severity=pattern_info.get('severity', 'HIGH'),
                        description=f'Potential injection vulnerability: {pattern_info["description"]}',
                        affected_urls=[flow.url],
                        evidence=[f'Injection pattern found in {location}'],
                        confidence=confidence,
                        impact='Application may be vulnerable to injection attacks',
                        remediation='Implement proper input validation and parameterized queries'
                    )
                    issues.append(issue)
        
        return issues
    
    def _check_authentication_issues(self, flow: NetworkFlow) -> List[SecurityIssue]:
        """Check for authentication-related security issues."""
        issues = []
        
        # Check for basic authentication over HTTP
        auth_header = flow.request_headers.get('Authorization', '')
        if auth_header.startswith('Basic ') and flow.scheme == 'http':
            evidence = NetworkConfidenceEvidence()
            evidence.pattern_match_quality = 1.0
            evidence.pattern_context_relevance = 1.0
            evidence.false_positive_likelihood = 0.0
            evidence.analysis_depth = 0.9
            
            confidence = self.confidence_calculator.calculate_network_confidence(
                finding_type='authentication_issues',
                evidence=evidence,
                pattern_id='authentication'
            )
            
            issue = SecurityIssue(
                issue_type=VulnerabilityType.AUTHENTICATION_BYPASS.value,
                severity='HIGH',
                description='Basic authentication over insecure HTTP',
                affected_urls=[flow.url],
                evidence=['Basic auth header found over HTTP connection'],
                confidence=confidence,
                impact='Authentication credentials transmitted in cleartext',
                remediation='Use HTTPS for all authenticated communications'
            )
            issues.append(issue)
        
        return issues
    
    def _check_security_headers(self, flow: NetworkFlow) -> List[SecurityIssue]:
        """Check for missing security headers in responses."""
        issues = []
        
        # Only check HTTPS responses
        if flow.scheme != 'https' or not flow.response_headers:
            return issues
        
        # Security headers to check
        security_headers = {
            'strict-transport-security': 'HSTS header missing',
            'content-security-policy': 'CSP header missing',
            'x-frame-options': 'X-Frame-Options header missing',
            'x-content-type-options': 'X-Content-Type-Options header missing'
        }
        
        response_headers_lower = {k.lower(): v for k, v in flow.response_headers.items()}
        
        for header, description in security_headers.items():
            if header not in response_headers_lower:
                evidence = NetworkConfidenceEvidence()
                evidence.pattern_match_quality = 1.0
                evidence.pattern_context_relevance = 0.8
                evidence.false_positive_likelihood = 0.0
                evidence.analysis_depth = 0.9
                
                confidence = self.confidence_calculator.calculate_network_confidence(
                    finding_type='missing_security_headers',
                    evidence=evidence
                )
                
                issue = SecurityIssue(
                    issue_type=VulnerabilityType.WEAK_TLS.value,
                    severity='MEDIUM',
                    description=description,
                    affected_urls=[flow.url],
                    evidence=[f'Missing {header} header in response'],
                    confidence=confidence,
                    impact='Missing security header may allow certain attacks',
                    remediation=f'Add {header} header to responses'
                )
                issues.append(issue)
        
        return issues
    
    def _deduplicate_security_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Remove duplicate security issues using unified deduplication framework."""
        if not issues:
            return issues
        
        # Convert SecurityIssue objects to dict format for unified framework
        findings = []
        for issue in issues:
            finding = {
                'title': f"{issue.issue_type} - {issue.severity}",
                'description': issue.description,
                'severity': issue.severity,
                'issue_type': issue.issue_type,
                'affected_urls': issue.affected_urls,
                'evidence': issue.evidence,
                'location': ', '.join(issue.affected_urls[:3]),  # Use first 3 URLs as location
                'original_object': issue  # Keep reference to original object
            }
            findings.append(finding)
        
        # Use unified deduplication framework with INTELLIGENT strategy
        try:
            # Create engine with appropriate strategy for network security issues
            engine = create_deduplication_engine(DeduplicationStrategy.INTELLIGENT)
            result = engine.deduplicate_findings(findings)
            
            # Convert back to SecurityIssue objects
            unique_issues = []
            for finding in result.unique_findings:
                if 'original_object' in finding:
                    # Use original object if available
                    unique_issues.append(finding['original_object'])
                else:
                    # Reconstruct SecurityIssue from consolidated finding
                    consolidated_issue = SecurityIssue(
                        issue_type=finding.get('issue_type', 'Unknown'),
                        severity=finding.get('severity', 'Unknown'),
                        description=finding.get('description', ''),
                        affected_urls=finding.get('affected_urls', []),
                        evidence=finding.get('evidence', [])
                    )
                    unique_issues.append(consolidated_issue)
            
            # Log deduplication results for transparency
            self.logger.info(f"Unified deduplication: {len(issues)} -> {len(unique_issues)} "
                           f"({result.metrics.duplicates_removed} duplicates removed)")
            
            return unique_issues
            
        except Exception as e:
            # Fallback to original logic if unified framework fails
            self.logger.warning(f"Unified deduplication failed, using fallback: {e}")
            return self._deduplicate_security_issues_fallback(issues)
    
    def _deduplicate_security_issues_fallback(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Fallback deduplication method (original logic)."""
        seen_issues = set()
        unique_issues = []
        
        for issue in issues:
            # Create signature for deduplication
            signature = (
                issue.issue_type,
                issue.severity,
                issue.description,
                tuple(sorted(issue.affected_urls))
            )
            
            if signature not in seen_issues:
                seen_issues.add(signature)
                unique_issues.append(issue)
            else:
                # Merge evidence from duplicate
                for existing_issue in unique_issues:
                    if (existing_issue.issue_type == issue.issue_type and 
                        existing_issue.description == issue.description):
                        existing_issue.evidence.extend(issue.evidence)
                        existing_issue.affected_urls.extend(issue.affected_urls)
                        # Remove duplicates
                        existing_issue.evidence = list(set(existing_issue.evidence))
                        existing_issue.affected_urls = list(set(existing_issue.affected_urls))
                        break
        
        return unique_issues
    
    def _generate_traffic_summary(self) -> TrafficSummary:
        """Generate comprehensive traffic summary."""
        if not self.flows:
            return TrafficSummary(0, 0, 0, 0, 0, 0, 0, 0.0, 0.0)
        
        # Calculate basic statistics
        total_requests = len(self.flows)
        unique_hosts = len(set(flow.host for flow in self.flows))
        http_requests = sum(1 for flow in self.flows if flow.scheme == 'http')
        https_requests = sum(1 for flow in self.flows if flow.scheme == 'https')
        
        # Estimate API requests (simplified)
        api_requests = sum(1 for flow in self.flows if self._is_api_request(flow))
        
        # Calculate data transfer
        data_uploaded = sum(len(flow.request_body) for flow in self.flows if flow.request_body)
        data_downloaded = sum(flow.response_size for flow in self.flows)
        
        # Calculate average response time
        response_times = [flow.duration for flow in self.flows if flow.duration > 0]
        average_response_time = sum(response_times) / len(response_times) if response_times else 0.0
        
        # Calculate security score
        security_score = self._calculate_security_score()
        
        return TrafficSummary(
            total_requests=total_requests,
            unique_hosts=unique_hosts,
            http_requests=http_requests,
            https_requests=https_requests,
            api_requests=api_requests,
            data_uploaded=data_uploaded,
            data_downloaded=data_downloaded,
            average_response_time=average_response_time,
            security_score=security_score
        )
    
    def _is_api_request(self, flow: NetworkFlow) -> bool:
        """Determine if request is an API call."""
        # Simple heuristics for API detection
        api_indicators = [
            '/api/',
            '/rest/',
            '.json',
            '/graphql',
            'application/json' in flow.request_headers.get('content-type', ''),
            'application/json' in flow.response_headers.get('content-type', '')
        ]
        
        return any(indicator in flow.url.lower() or indicator in str(flow.request_headers).lower() 
                  for indicator in api_indicators)
    
    def _calculate_security_score(self) -> float:
        """Calculate overall security score for traffic."""
        if not self.flows:
            return 0.0
        
        # Start with base score
        base_score = 100.0
        
        # Deduct points for security issues
        for issue in self.security_issues:
            severity_deduction = {
                'CRITICAL': 20,
                'HIGH': 15,
                'MEDIUM': 10,
                'LOW': 5
            }
            deduction = severity_deduction.get(issue.severity, 5)
            base_score -= deduction * issue.confidence
        
        # Deduct points for HTTP usage
        http_ratio = sum(1 for flow in self.flows if flow.scheme == 'http') / len(self.flows)
        base_score -= http_ratio * 30
        
        # Ensure score is between 0 and 100
        return max(0.0, min(100.0, base_score))
    
    def classify_traffic(self) -> Dict[str, Any]:
        """Classify traffic by type and security level."""
        classification = {
            'by_protocol': {'http': 0, 'https': 0, 'other': 0},
            'by_type': {'api': 0, 'web': 0, 'media': 0, 'other': 0},
            'by_security': {'secure': 0, 'acceptable': 0, 'suspicious': 0, 'insecure': 0}
        }
        
        for flow in self.flows:
            # Protocol classification
            if flow.scheme == 'http':
                classification['by_protocol']['http'] += 1
            elif flow.scheme == 'https':
                classification['by_protocol']['https'] += 1
            else:
                classification['by_protocol']['other'] += 1
            
            # Type classification
            if self._is_api_request(flow):
                classification['by_type']['api'] += 1
            elif any(ext in flow.path.lower() for ext in ['.jpg', '.png', '.gif', '.mp4', '.mp3']):
                classification['by_type']['media'] += 1
            elif any(ext in flow.path.lower() for ext in ['.html', '.css', '.js']):
                classification['by_type']['web'] += 1
            else:
                classification['by_type']['other'] += 1
            
            # Security classification
            security_level = self._classify_flow_security(flow)
            classification['by_security'][security_level] += 1
        
        return classification
    
    def _classify_flow_security(self, flow: NetworkFlow) -> str:
        """Classify individual flow security level."""
        # Check if flow has associated security issues
        flow_issues = [issue for issue in self.security_issues if flow.url in issue.affected_urls]
        
        if not flow_issues:
            return 'secure' if flow.scheme == 'https' else 'acceptable'
        
        # Classify based on highest severity issue
        severities = [issue.severity for issue in flow_issues]
        
        if 'CRITICAL' in severities:
            return 'insecure'
        elif 'HIGH' in severities:
            return 'suspicious'
        elif 'MEDIUM' in severities:
            return 'suspicious'
        else:
            return 'acceptable'

def create_traffic_analyzer(
    config: Dict[str, Any], 
    confidence_calculator: NetworkConfidenceCalculator
) -> NetworkTrafficAnalyzer:
    """
    Factory function to create traffic analyzer with dependencies.
    
    Args:
        config: Network patterns configuration
        confidence_calculator: confidence calculator
        
    Returns:
        Configured traffic analyzer
    """
    return NetworkTrafficAnalyzer(config, confidence_calculator) 