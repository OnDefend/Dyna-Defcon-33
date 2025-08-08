#!/usr/bin/env python3
"""
Test Result Correlation Engine

Advanced correlation engine specifically designed for the Dynamic Analysis Coordinator
to intelligently merge, deduplicate, and prioritize findings from multiple dynamic 
analysis components. Unlike basic result aggregation, this engine uses sophisticated
correlation algorithms to identify related findings, eliminate duplicates, and 
provide comprehensive security insights.

Key Features:
- Multi-component finding correlation and deduplication
- Temporal correlation for related security events
- Confidence-based finding prioritization and ranking
- Cross-component vulnerability validation and confirmation
- Advanced false positive detection and filtering
- Intelligent finding clustering and categorization

Supported Components:
- Runtime Vulnerability Patterns: Real-time pattern-based detection
- ContinuousMonitoringEngine: Runtime behavior and decryption monitoring
- AdvancedDynamicAnalysisOrchestrator: Comprehensive security analysis
- DynamicLogAnalyzer: Log-based security event detection

Correlation Strategies:
- Temporal Correlation: Events occurring within time windows
- Signature Correlation: Similar API calls, parameters, or patterns
- Semantic Correlation: Related security concepts and vulnerability types
- Evidence Correlation: Supporting evidence from multiple sources
"""

import logging
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import re


class CorrelationStrategy(Enum):
    """Strategies for correlating findings across components."""
    TEMPORAL = "temporal"
    SIGNATURE = "signature"
    SEMANTIC = "semantic"
    EVIDENCE = "evidence"
    PATTERN = "pattern"


class CorrelationConfidence(Enum):
    """Confidence levels for correlation results."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class FindingSeverity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CorrelatedFinding:
    """Represents a correlated finding from multiple sources."""
    primary_finding: Dict[str, Any]
    correlated_findings: List[Dict[str, Any]] = field(default_factory=list)
    correlation_strategies: List[CorrelationStrategy] = field(default_factory=list)
    correlation_confidence: float = 0.0
    combined_confidence: float = 0.0
    final_severity: FindingSeverity = FindingSeverity.MEDIUM
    
    # Metadata
    finding_id: str = ""
    timestamp: float = field(default_factory=time.time)
    component_sources: Set[str] = field(default_factory=set)
    
    # Evidence aggregation
    consolidated_evidence: List[str] = field(default_factory=list)
    validation_count: int = 0
    false_positive_indicators: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = self._generate_finding_id()
        
        # Extract component sources
        self.component_sources.add(self.primary_finding.get('component', 'unknown'))
        for finding in self.correlated_findings:
            self.component_sources.add(finding.get('component', 'unknown'))
    
    def _generate_finding_id(self) -> str:
        """Generate unique finding ID based on content."""
        content = str(self.primary_finding.get('pattern_name', '')) + str(self.timestamp)
        return hashlib.md5(content.encode()).hexdigest()[:12]


@dataclass
class CorrelationResult:
    """Results from the correlation engine analysis."""
    correlated_findings: List[CorrelatedFinding] = field(default_factory=list)
    uncorrelated_findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # Statistics
    total_input_findings: int = 0
    correlation_rate: float = 0.0
    false_positive_rate: float = 0.0
    confidence_distribution: Dict[str, int] = field(default_factory=dict)
    
    # Component analysis
    component_contribution: Dict[str, int] = field(default_factory=dict)
    cross_component_correlations: int = 0
    
    # Performance metrics
    correlation_time_ms: float = 0.0
    processing_overhead: float = 0.0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get correlation result summary."""
        return {
            'total_findings': len(self.correlated_findings) + len(self.uncorrelated_findings),
            'correlated_findings': len(self.correlated_findings),
            'uncorrelated_findings': len(self.uncorrelated_findings),
            'correlation_rate': self.correlation_rate,
            'cross_component_correlations': self.cross_component_correlations,
            'component_contribution': dict(self.component_contribution),
            'confidence_distribution': dict(self.confidence_distribution),
            'processing_time_ms': self.correlation_time_ms
        }


class TestResultCorrelationEngine:
    """
    Advanced correlation engine for dynamic analysis findings.
    
    Intelligently correlates findings from multiple dynamic analysis components
    using temporal, semantic, and evidence-based correlation strategies to
    provide comprehensive and accurate security assessment results.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize correlation engine with configuration."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Correlation configuration
        self.temporal_window_seconds = self.config.get('temporal_window_seconds', 30.0)
        self.min_correlation_confidence = self.config.get('min_correlation_confidence', 0.6)
        self.max_correlation_distance = self.config.get('max_correlation_distance', 0.8)
        
        # False positive detection
        self.false_positive_threshold = self.config.get('false_positive_threshold', 0.3)
        self.enable_false_positive_filtering = self.config.get('enable_false_positive_filtering', True)
        
        # Performance configuration
        self.max_findings_per_component = self.config.get('max_findings_per_component', 1000)
        self.enable_clustering = self.config.get('enable_clustering', True)
        
        # Correlation state
        self.correlation_history: List[CorrelationResult] = []
        self.learning_data: Dict[str, Any] = defaultdict(list)
        
    def correlate_findings(self, component_results: Dict[str, Any]) -> CorrelationResult:
        """
        Correlate findings from multiple dynamic analysis components.
        
        Args:
            component_results: Results from different components
            
        Returns:
            CorrelationResult: Comprehensive correlation analysis
        """
        start_time = time.time()
        self.logger.info("🔗 Starting advanced finding correlation...")
        
        # Extract and normalize findings from all components
        all_findings = self._extract_all_findings(component_results)
        
        if not all_findings:
            self.logger.warning("No findings to correlate")
            return CorrelationResult(total_input_findings=0)
        
        # Perform correlation strategies
        correlation_result = CorrelationResult(total_input_findings=len(all_findings))
        
        # 1. Temporal correlation
        temporal_groups = self._perform_temporal_correlation(all_findings)
        
        # 2. Signature correlation
        signature_groups = self._perform_signature_correlation(all_findings)
        
        # 3. Semantic correlation
        semantic_groups = self._perform_semantic_correlation(all_findings)
        
        # 4. Evidence correlation
        evidence_groups = self._perform_evidence_correlation(all_findings)
        
        # 5. Merge correlation strategies
        correlated_findings = self._merge_correlation_strategies(
            all_findings, temporal_groups, signature_groups, semantic_groups, evidence_groups
        )
        
        # 6. Apply false positive filtering
        if self.enable_false_positive_filtering:
            correlated_findings = self._filter_false_positives(correlated_findings)
        
        # 7. Calculate final statistics
        correlation_result.correlated_findings = correlated_findings
        correlation_result.uncorrelated_findings = self._get_uncorrelated_findings(
            all_findings, correlated_findings
        )
        
        # 8. Calculate metrics
        self._calculate_correlation_metrics(correlation_result)
        correlation_result.correlation_time_ms = (time.time() - start_time) * 1000
        
        # Store for learning
        self.correlation_history.append(correlation_result)
        
        self.logger.info(f"✅ Correlation completed: {len(correlated_findings)} correlated findings "
                        f"({correlation_result.correlation_rate:.1%} correlation rate)")
        
        return correlation_result
    
    def _extract_all_findings(self, component_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and normalize findings from all components."""
        all_findings = []
        
        for component_name, results in component_results.items():
            if not results:
                continue
                
            component_findings = []
            
            # Handle different component result formats
            if component_name == 'runtime_patterns':
                component_findings = self._extract_runtime_pattern_findings(results)
            elif component_name == 'monitoring_engine':
                component_findings = self._extract_monitoring_findings(results)
            elif component_name == 'orchestrator':
                component_findings = self._extract_orchestrator_findings(results)
            elif component_name == 'log_analyzer':
                component_findings = self._extract_log_analyzer_findings(results)
            else:
                # Generic extraction
                component_findings = self._extract_generic_findings(results, component_name)
            
            # Normalize and add component metadata
            for finding in component_findings:
                finding['component'] = component_name
                finding['extraction_timestamp'] = time.time()
                all_findings.append(finding)
        
        self.logger.debug(f"Extracted {len(all_findings)} findings from {len(component_results)} components")
        return all_findings
    
    def _extract_runtime_pattern_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from runtime pattern detection results."""
        findings = []
        pattern_matches = results.get('pattern_matches', [])
        
        for match in pattern_matches:
            finding = {
                'type': 'runtime_pattern',
                'pattern_id': match.pattern_id,
                'pattern_name': match.pattern_name,
                'severity': match.severity.value,
                'confidence': match.confidence,
                'cwe_id': match.cwe_id,
                'masvs_category': match.masvs_category,
                'description': match.description,
                'evidence_count': len(match.evidence),
                'timestamp': match.timestamp,
                'evidence': [
                    {
                        'trigger_type': ev.trigger_type.value,
                        'api_signature': ev.api_signature,
                        'timestamp': ev.timestamp
                    } for ev in match.evidence
                ]
            }
            findings.append(finding)
        
        return findings
    
    def _extract_monitoring_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from continuous monitoring engine results."""
        # Placeholder for monitoring engine findings extraction
        findings = []
        
        # Handle monitoring results format
        if isinstance(results, dict):
            for key, value in results.items():
                if 'vulnerability' in key.lower() or 'finding' in key.lower():
                    finding = {
                        'type': 'monitoring',
                        'finding_key': key,
                        'severity': 'medium',  # Default
                        'confidence': 0.7,     # Default
                        'timestamp': time.time(),
                        'data': value
                    }
                    findings.append(finding)
        
        return findings
    
    def _extract_orchestrator_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from advanced dynamic analysis orchestrator."""
        findings = []
        
        # Handle orchestrator results format
        if hasattr(results, 'vulnerabilities'):
            vulnerabilities = results.vulnerabilities
        elif isinstance(results, dict):
            vulnerabilities = results.get('vulnerabilities', [])
        else:
            vulnerabilities = []
        
        for vuln in vulnerabilities:
            finding = {
                'type': 'orchestrator',
                'vulnerability_type': vuln.get('type', 'unknown'),
                'severity': vuln.get('severity', 'medium'),
                'confidence': vuln.get('confidence', 0.7),
                'timestamp': vuln.get('timestamp', time.time()),
                'details': vuln.get('details', {}),
                'location': vuln.get('location', '')
            }
            findings.append(finding)
        
        return findings
    
    def _extract_log_analyzer_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from dynamic log analyzer."""
        findings = []
        
        # Handle log analyzer results
        security_events = results.get('security_events', [])
        for event in security_events:
            finding = {
                'type': 'log_event',
                'event_type': event.get('type', 'unknown'),
                'severity': event.get('severity', 'medium'),
                'confidence': event.get('confidence', 0.6),
                'timestamp': event.get('timestamp', time.time()),
                'message': event.get('message', ''),
                'source': event.get('source', 'logcat')
            }
            findings.append(finding)
        
        return findings
    
    def _extract_generic_findings(self, results: Any, component_name: str) -> List[Dict[str, Any]]:
        """Extract findings from generic component results."""
        findings = []
        
        if isinstance(results, dict):
            finding = {
                'type': 'generic',
                'component_specific': True,
                'severity': 'medium',
                'confidence': 0.5,
                'timestamp': time.time(),
                'raw_results': results
            }
            findings.append(finding)
        
        return findings
    
    def _perform_temporal_correlation(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by temporal proximity."""
        temporal_groups = defaultdict(list)
        
        # Sort findings by timestamp
        sorted_findings = sorted(findings, key=lambda f: f.get('timestamp', 0))
        
        for i, finding in enumerate(sorted_findings):
            finding_time = finding.get('timestamp', 0)
            group_key = f"temporal_{int(finding_time // self.temporal_window_seconds)}"
            temporal_groups[group_key].append(finding)
        
        # Filter groups with multiple findings
        correlated_groups = {k: v for k, v in temporal_groups.items() if len(v) > 1}
        
        self.logger.debug(f"Temporal correlation found {len(correlated_groups)} groups")
        return correlated_groups
    
    def _perform_signature_correlation(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by similar signatures or patterns."""
        signature_groups = defaultdict(list)
        
        for finding in findings:
            # Generate signature based on finding characteristics
            signature_elements = []
            
            if 'pattern_name' in finding:
                signature_elements.append(finding['pattern_name'])
            if 'cwe_id' in finding:
                signature_elements.append(finding['cwe_id'])
            if 'vulnerability_type' in finding:
                signature_elements.append(finding['vulnerability_type'])
            if 'api_signature' in finding:
                signature_elements.append(finding['api_signature'])
            
            if signature_elements:
                signature = '_'.join(signature_elements)
                signature_groups[signature].append(finding)
        
        # Filter groups with multiple findings
        correlated_groups = {k: v for k, v in signature_groups.items() if len(v) > 1}
        
        self.logger.debug(f"Signature correlation found {len(correlated_groups)} groups")
        return correlated_groups
    
    def _perform_semantic_correlation(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by semantic similarity."""
        semantic_groups = defaultdict(list)
        
        # Define semantic categories
        semantic_categories = {
            'network_security': ['http', 'https', 'certificate', 'ssl', 'tls', 'network'],
            'data_protection': ['storage', 'external', 'logging', 'sensitive', 'data'],
            'cryptographic': ['crypto', 'cipher', 'key', 'encryption', 'hash'],
            'authentication': ['auth', 'login', 'password', 'token', 'session'],
            'injection': ['injection', 'sql', 'xss', 'script', 'command']
        }
        
        for finding in findings:
            # Extract text content for semantic analysis
            text_content = []
            text_content.append(finding.get('description', '').lower())
            text_content.append(finding.get('pattern_name', '').lower())
            text_content.append(finding.get('vulnerability_type', '').lower())
            text_content.append(finding.get('message', '').lower())
            
            full_text = ' '.join(text_content)
            
            # Categorize by semantic similarity
            for category, keywords in semantic_categories.items():
                if any(keyword in full_text for keyword in keywords):
                    semantic_groups[category].append(finding)
                    break
        
        # Filter groups with multiple findings
        correlated_groups = {k: v for k, v in semantic_groups.items() if len(v) > 1}
        
        self.logger.debug(f"Semantic correlation found {len(correlated_groups)} groups")
        return correlated_groups
    
    def _perform_evidence_correlation(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by supporting evidence."""
        evidence_groups = defaultdict(list)
        
        for finding in findings:
            evidence_key = None
            
            # Extract evidence identifiers
            if 'evidence' in finding and finding['evidence']:
                # Use API signatures from evidence
                api_signatures = [ev.get('api_signature', '') for ev in finding['evidence'] 
                                if ev.get('api_signature')]
                if api_signatures:
                    evidence_key = f"api_{api_signatures[0]}"
            
            elif 'location' in finding and finding['location']:
                evidence_key = f"location_{finding['location']}"
                
            elif 'source' in finding and finding['source']:
                evidence_key = f"source_{finding['source']}"
            
            if evidence_key:
                evidence_groups[evidence_key].append(finding)
        
        # Filter groups with multiple findings
        correlated_groups = {k: v for k, v in evidence_groups.items() if len(v) > 1}
        
        self.logger.debug(f"Evidence correlation found {len(correlated_groups)} groups")
        return correlated_groups
    
    def _merge_correlation_strategies(self, all_findings: List[Dict[str, Any]], 
                                    temporal_groups: Dict[str, List[Dict[str, Any]]],
                                    signature_groups: Dict[str, List[Dict[str, Any]]],
                                    semantic_groups: Dict[str, List[Dict[str, Any]]],
                                    evidence_groups: Dict[str, List[Dict[str, Any]]]) -> List[CorrelatedFinding]:
        """Merge results from different correlation strategies."""
        correlated_findings = []
        processed_finding_ids = set()
        
        # Process each finding and determine its correlations
        for finding in all_findings:
            finding_id = id(finding)
            
            if finding_id in processed_finding_ids:
                continue
            
            # Find correlations across different strategies
            correlated_list = [finding]
            correlation_strategies = []
            
            # Check temporal correlations
            for group in temporal_groups.values():
                if finding in group:
                    correlated_list.extend([f for f in group if f != finding])
                    correlation_strategies.append(CorrelationStrategy.TEMPORAL)
                    break
            
            # Check signature correlations
            for group in signature_groups.values():
                if finding in group:
                    for f in group:
                        if f != finding and f not in correlated_list:
                            correlated_list.append(f)
                    if CorrelationStrategy.SIGNATURE not in correlation_strategies:
                        correlation_strategies.append(CorrelationStrategy.SIGNATURE)
                    break
            
            # Check semantic correlations
            for group in semantic_groups.values():
                if finding in group:
                    for f in group:
                        if f != finding and f not in correlated_list:
                            correlated_list.append(f)
                    if CorrelationStrategy.SEMANTIC not in correlation_strategies:
                        correlation_strategies.append(CorrelationStrategy.SEMANTIC)
                    break
            
            # Check evidence correlations
            for group in evidence_groups.values():
                if finding in group:
                    for f in group:
                        if f != finding and f not in correlated_list:
                            correlated_list.append(f)
                    if CorrelationStrategy.EVIDENCE not in correlation_strategies:
                        correlation_strategies.append(CorrelationStrategy.EVIDENCE)
                    break
            
            # Create correlated finding
            if len(correlated_list) > 1 or correlation_strategies:
                primary_finding = finding
                supporting_findings = correlated_list[1:] if len(correlated_list) > 1 else []
                
                correlated_finding = CorrelatedFinding(
                    primary_finding=primary_finding,
                    correlated_findings=supporting_findings,
                    correlation_strategies=correlation_strategies,
                    correlation_confidence=self._calculate_correlation_confidence(
                        correlation_strategies, len(correlated_list)
                    ),
                    combined_confidence=self._calculate_combined_confidence(correlated_list),
                    validation_count=len(supporting_findings)
                )
                
                correlated_findings.append(correlated_finding)
                
                # Mark all correlated findings as processed
                for f in correlated_list:
                    processed_finding_ids.add(id(f))
        
        return correlated_findings
    
    def _calculate_correlation_confidence(self, strategies: List[CorrelationStrategy], 
                                        correlation_count: int) -> float:
        """Calculate confidence score for correlation."""
        base_confidence = 0.5
        
        # Boost confidence based on number of strategies
        strategy_boost = len(strategies) * 0.15
        
        # Boost confidence based on correlation count
        count_boost = min(0.3, (correlation_count - 1) * 0.1)
        
        confidence = min(1.0, base_confidence + strategy_boost + count_boost)
        return confidence
    
    def _calculate_combined_confidence(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate combined confidence from multiple findings."""
        if not findings:
            return 0.0
        
        confidences = [f.get('confidence', 0.5) for f in findings]
        
        # Use weighted average with diminishing returns
        weights = [1.0 / (i + 1) for i in range(len(confidences))]
        weighted_sum = sum(c * w for c, w in zip(confidences, weights))
        weight_sum = sum(weights)
        
        return min(1.0, weighted_sum / weight_sum * 1.2)  # 20% boost for correlation
    
    def _filter_false_positives(self, correlated_findings: List[CorrelatedFinding]) -> List[CorrelatedFinding]:
        """Filter potential false positives based on various indicators."""
        filtered_findings = []
        
        for finding in correlated_findings:
            false_positive_score = 0.0
            indicators = []
            
            # Check for low confidence
            if finding.combined_confidence < 0.3:
                false_positive_score += 0.4
                indicators.append("low_confidence")
            
            # Check for single source with no correlation
            if len(finding.component_sources) == 1 and not finding.correlated_findings:
                false_positive_score += 0.3
                indicators.append("single_source_no_correlation")
            
            # Check for generic patterns
            finding_text = str(finding.primary_finding).lower()
            generic_patterns = ['unknown', 'generic', 'default', 'test']
            if any(pattern in finding_text for pattern in generic_patterns):
                false_positive_score += 0.2
                indicators.append("generic_pattern")
            
            finding.false_positive_indicators = indicators
            
            # Keep finding if below false positive threshold
            if false_positive_score < self.false_positive_threshold:
                filtered_findings.append(finding)
            else:
                self.logger.debug(f"Filtered potential false positive: {finding.finding_id} "
                                f"(score: {false_positive_score:.2f})")
        
        return filtered_findings
    
    def _get_uncorrelated_findings(self, all_findings: List[Dict[str, Any]], 
                                 correlated_findings: List[CorrelatedFinding]) -> List[Dict[str, Any]]:
        """Get findings that weren't correlated."""
        correlated_finding_ids = set()
        
        for cf in correlated_findings:
            correlated_finding_ids.add(id(cf.primary_finding))
            for f in cf.correlated_findings:
                correlated_finding_ids.add(id(f))
        
        uncorrelated = [f for f in all_findings if id(f) not in correlated_finding_ids]
        return uncorrelated
    
    def _calculate_correlation_metrics(self, result: CorrelationResult):
        """Calculate comprehensive correlation metrics."""
        if result.total_input_findings == 0:
            return
        
        # Basic correlation rate
        correlated_count = sum(1 + len(cf.correlated_findings) for cf in result.correlated_findings)
        result.correlation_rate = correlated_count / result.total_input_findings
        
        # Confidence distribution
        for cf in result.correlated_findings:
            confidence_level = "high" if cf.correlation_confidence > 0.8 else \
                             "medium" if cf.correlation_confidence > 0.5 else "low"
            result.confidence_distribution[confidence_level] = \
                result.confidence_distribution.get(confidence_level, 0) + 1
        
        # Component contribution
        for cf in result.correlated_findings:
            for component in cf.component_sources:
                result.component_contribution[component] = \
                    result.component_contribution.get(component, 0) + 1
        
        # Cross-component correlations
        result.cross_component_correlations = sum(
            1 for cf in result.correlated_findings if len(cf.component_sources) > 1
        )


def create_correlation_engine(config: Optional[Dict[str, Any]] = None) -> TestResultCorrelationEngine:
    """Create and configure a test result correlation engine."""
    return TestResultCorrelationEngine(config)


def main():
    """Demonstration of test result correlation engine."""
    print("🔗 Test Result Correlation Engine - Advanced Analysis")
    print("=" * 60)
    
    # Create correlation engine
    engine = create_correlation_engine()
    
    print("✅ Correlation Engine Initialized")
    print("\nKey Features:")
    print("  - Multi-component finding correlation and deduplication")
    print("  - Temporal, signature, semantic, and evidence correlation")
    print("  - Advanced false positive detection and filtering")
    print("  - Confidence-based finding prioritization")
    print("  - Cross-component vulnerability validation")
    print("  - Intelligent finding clustering and categorization")
    
    print(f"\nConfiguration:")
    print(f"  - Temporal window: {engine.temporal_window_seconds}s")
    print(f"  - Min correlation confidence: {engine.min_correlation_confidence}")
    print(f"  - False positive threshold: {engine.false_positive_threshold}")
    print(f"  - False positive filtering: {engine.enable_false_positive_filtering}")


if __name__ == "__main__":
    main() 