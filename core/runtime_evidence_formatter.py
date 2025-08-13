#!/usr/bin/env python3
"""
Runtime Evidence Formatter

Formats runtime vulnerabilities with complete execution evidence and provides
enhanced vulnerability categorization by detection method.

Author: AODS Team
Date: January 2025
"""

import logging
import time
import json
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import hashlib


class DetectionCategory(Enum):
    """Categories of vulnerability detection methods."""
    RUNTIME_ONLY = "runtime_only"                              # Only detectable during runtime
    STATIC_CONFIRMED_RUNTIME = "static_confirmed_runtime"      # Static finding confirmed by runtime
    STATIC_ONLY = "static_only"                               # Only detectable via static analysis
    CONFIGURATION_ONLY = "configuration_only"                 # Only detectable via configuration analysis
    HYBRID_DETECTION = "hybrid_detection"                     # Detected by multiple methods
    UNKNOWN_CATEGORY = "unknown_category"                     # Cannot determine category


class EvidenceQuality(Enum):
    """Quality levels of runtime evidence."""
    COMPLETE = "complete"          # Full stack trace, context, and parameters
    PARTIAL = "partial"            # Some runtime evidence missing
    MINIMAL = "minimal"            # Basic runtime indicators only
    INSUFFICIENT = "insufficient"  # Not enough evidence for runtime classification


@dataclass
class RuntimeEvidencePackage:
    """Complete runtime evidence package for a vulnerability."""
    hook_timestamp: float
    formatted_timestamp: str
    call_stack: List[str]
    execution_context: Dict[str, Any]
    runtime_parameters: Dict[str, Any]
    frida_session_info: Dict[str, Any] = field(default_factory=dict)
    evidence_quality: EvidenceQuality = EvidenceQuality.INSUFFICIENT
    evidence_hash: str = field(default="")
    collection_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Calculate evidence hash and quality assessment."""
        if not self.evidence_hash:
            evidence_data = {
                'hook_timestamp': self.hook_timestamp,
                'call_stack': self.call_stack,
                'execution_context': self.execution_context,
                'runtime_parameters': self.runtime_parameters
            }
            evidence_str = json.dumps(evidence_data, sort_keys=True, default=str)
            self.evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()[:16]
        
        if not self.formatted_timestamp:
            self.formatted_timestamp = datetime.fromtimestamp(self.hook_timestamp).isoformat()
        
        # Assess evidence quality
        if not self.evidence_quality or self.evidence_quality == EvidenceQuality.INSUFFICIENT:
            self.evidence_quality = self._assess_evidence_quality()
    
    def _assess_evidence_quality(self) -> EvidenceQuality:
        """Assess the quality of runtime evidence."""
        score = 0
        
        # Check for complete stack trace
        if self.call_stack and len(self.call_stack) >= 2:
            score += 2
        elif self.call_stack:
            score += 1
        
        # Check for execution context
        if self.execution_context and len(self.execution_context) >= 3:
            score += 2
        elif self.execution_context:
            score += 1
        
        # Check for runtime parameters
        if self.runtime_parameters and len(self.runtime_parameters) >= 2:
            score += 2
        elif self.runtime_parameters:
            score += 1
        
        # Check for timestamp validity
        if self.hook_timestamp > 0:
            score += 1
        
        # Determine quality based on score
        if score >= 6:
            return EvidenceQuality.COMPLETE
        elif score >= 4:
            return EvidenceQuality.PARTIAL
        elif score >= 2:
            return EvidenceQuality.MINIMAL
        else:
            return EvidenceQuality.INSUFFICIENT


@dataclass
class FormattedVulnerability:
    """Formatted vulnerability with enhanced evidence and categorization."""
    vulnerability_id: str
    title: str
    description: str
    severity: str
    confidence: float
    detection_category: DetectionCategory
    source_classification: str
    detection_method: str
    analysis_phase: str
    evidence_type: str
    runtime_evidence: Optional[RuntimeEvidencePackage] = None
    static_evidence: Dict[str, Any] = field(default_factory=dict)
    configuration_evidence: Dict[str, Any] = field(default_factory=dict)
    actionable_information: Dict[str, Any] = field(default_factory=dict)
    formatting_metadata: Dict[str, Any] = field(default_factory=dict)
    # **CRITICAL**: Code evidence for security professionals
    code_snippet: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    surrounding_context: Optional[str] = None


class RuntimeEvidenceFormatter:
    """
    Formats runtime vulnerabilities with complete execution evidence and provides
    enhanced vulnerability categorization by detection method.
    """
    
    def __init__(self):
        """Initialize runtime evidence formatter."""
        self.logger = logging.getLogger(__name__)
        
        # Evidence quality thresholds
        self.quality_thresholds = {
            'complete_evidence_score': 6,
            'partial_evidence_score': 4,
            'minimal_evidence_score': 2
        }
        
        # Detection method mappings
        self.runtime_detection_methods = {
            'frida_runtime_instrumentation',
            'frida_dynamic_analysis',
            'runtime_hooks',
            'dynamic_instrumentation'
        }
        
        self.static_detection_methods = {
            'jadx_static_analysis',
            'static_code_analysis',
            'decompilation_analysis',
            'bytecode_analysis'
        }
        
        self.config_detection_methods = {
            'manifest_analysis',
            'configuration_review',
            'permission_analysis',
            'intent_filter_analysis'
        }
        
        self.logger.info("🎯 RuntimeEvidenceFormatter initialized")
    
    def format_runtime_vulnerability(self, vulnerability: Union[Dict[str, Any], Any]) -> FormattedVulnerability:
        """
        Format runtime vulnerability with complete evidence.
        
        Args:
            vulnerability: Vulnerability object or dictionary
            
        Returns:
            FormattedVulnerability with enhanced evidence and categorization
        """
        try:
            # Normalize vulnerability data
            vuln_data = self._normalize_vulnerability_data(vulnerability)
            
            # Extract basic vulnerability information
            vuln_id = vuln_data.get('origin_id', vuln_data.get('id', f"vuln_{int(time.time())}"))
            title = vuln_data.get('title', 'Unknown Vulnerability')
            description = vuln_data.get('description', '')
            severity = vuln_data.get('severity', 'UNKNOWN').upper()
            confidence = float(vuln_data.get('confidence', 0.0))
            
            # Extract classification information
            source_classification = vuln_data.get('source', 'unknown_source')
            detection_method = vuln_data.get('detection_method', 'unknown_method')
            analysis_phase = vuln_data.get('analysis_phase', 'unknown_phase')
            evidence_type = vuln_data.get('evidence_type', 'no_evidence')
            
            # Determine detection category
            detection_category = self._determine_detection_category(vuln_data)
            
            # Extract runtime evidence if available
            runtime_evidence = self._extract_runtime_evidence_package(vuln_data)
            
            # Extract static evidence
            static_evidence = self._extract_static_evidence(vuln_data)
            
            # Extract configuration evidence
            config_evidence = self._extract_configuration_evidence(vuln_data)
            
            # Generate actionable information
            actionable_info = self._generate_actionable_information(vuln_data, detection_category)
            
            # **CRITICAL**: Extract code evidence for security professionals
            code_snippet = vuln_data.get('code_snippet')
            file_path = vuln_data.get('file_path')
            line_number = vuln_data.get('line_number')
            surrounding_context = vuln_data.get('surrounding_context')
            
            # Create formatting metadata
            formatting_metadata = {
                'formatter_version': '1.0',
                'formatting_timestamp': time.time(),
                'evidence_quality': runtime_evidence.evidence_quality.value if runtime_evidence else 'no_runtime_evidence',
                'categorization_confidence': self._calculate_categorization_confidence(vuln_data),
                'original_plugin': vuln_data.get('plugin_name', 'unknown'),
                'classification_confidence': vuln_data.get('classification_confidence', 0.0),
                'has_code_snippet': bool(code_snippet),
                'has_file_location': bool(file_path and line_number)
            }
            
            formatted_vuln = FormattedVulnerability(
                vulnerability_id=vuln_id,
                title=title,
                description=description,
                severity=severity,
                confidence=confidence,
                detection_category=detection_category,
                source_classification=source_classification,
                detection_method=detection_method,
                analysis_phase=analysis_phase,
                evidence_type=evidence_type,
                runtime_evidence=runtime_evidence,
                static_evidence=static_evidence,
                configuration_evidence=config_evidence,
                actionable_information=actionable_info,
                formatting_metadata=formatting_metadata,
                # **CRITICAL**: Include code evidence
                code_snippet=code_snippet,
                file_path=file_path,
                line_number=line_number,
                surrounding_context=surrounding_context
            )
            
            self.logger.debug(f"🎯 Formatted vulnerability: {title} "
                            f"(category: {detection_category.value}, quality: {runtime_evidence.evidence_quality.value if runtime_evidence else 'N/A'})")
            
            return formatted_vuln
            
        except Exception as e:
            self.logger.error(f"❌ Vulnerability formatting failed: {e}")
            # Return minimal formatted vulnerability
            return FormattedVulnerability(
                vulnerability_id=f"error_{int(time.time())}",
                title="Formatting Error",
                description=f"Failed to format vulnerability: {e}",
                severity="UNKNOWN",
                confidence=0.0,
                detection_category=DetectionCategory.UNKNOWN_CATEGORY,
                source_classification="unknown_source",
                detection_method="unknown_method",
                analysis_phase="unknown_phase",
                evidence_type="no_evidence",
                formatting_metadata={'error': str(e)}
            )
    
    def categorize_by_detection_method(self, vulnerabilities: List[Union[Dict[str, Any], Any]]) -> Dict[str, List[FormattedVulnerability]]:
        """
        Categorize vulnerabilities by actual detection method.
        
        Args:
            vulnerabilities: List of vulnerability objects or dictionaries
            
        Returns:
            Dictionary with categorized and formatted vulnerabilities
        """
        categories = {
            'runtime_only': [],              # Only detectable during runtime
            'static_confirmed_runtime': [],  # Static finding confirmed by runtime
            'static_only': [],              # Only detectable via static analysis
            'configuration_only': [],       # Only detectable via configuration analysis
            'hybrid_detection': [],         # Detected by multiple methods
            'unknown_category': []          # Cannot determine category
        }
        
        for vuln in vulnerabilities:
            try:
                # Format the vulnerability
                formatted_vuln = self.format_runtime_vulnerability(vuln)
                
                # Add to appropriate category
                category_key = formatted_vuln.detection_category.value
                if category_key in categories:
                    categories[category_key].append(formatted_vuln)
                else:
                    categories['unknown_category'].append(formatted_vuln)
                    
            except Exception as e:
                self.logger.error(f"❌ Failed to categorize vulnerability: {e}")
                continue
        
        # Log categorization summary
        self.logger.info(f"📊 Vulnerability Categorization Summary:")
        for category, vulns in categories.items():
            if vulns:
                self.logger.info(f"   🔍 {category}: {len(vulns)} vulnerabilities")
        
        return categories
    
    def _normalize_vulnerability_data(self, vulnerability: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """Normalize vulnerability data to dictionary format."""
        if isinstance(vulnerability, dict):
            return vulnerability
        elif hasattr(vulnerability, 'to_dict'):
            return vulnerability.to_dict()
        elif hasattr(vulnerability, '__dict__'):
            return vulnerability.__dict__
        else:
            # Extract common attributes
            vuln_data = {}
            for attr in ['id', 'title', 'description', 'severity', 'confidence', 'source', 'plugin_name']:
                if hasattr(vulnerability, attr):
                    vuln_data[attr] = getattr(vulnerability, attr)
            return vuln_data
    
    def _determine_detection_category(self, vuln_data: Dict[str, Any]) -> DetectionCategory:
        """Determine the detection category for a vulnerability."""
        
        detection_method = vuln_data.get('detection_method', '').lower()
        source_classification = vuln_data.get('source', '').lower()
        evidence_type = vuln_data.get('evidence_type', '').lower()
        
        # Check for runtime-only detection
        if (detection_method in self.runtime_detection_methods or
            'runtime' in source_classification and 'static' not in source_classification):
            
            # Check if this is runtime-only or static confirmed by runtime
            if self._has_static_indicators(vuln_data):
                return DetectionCategory.STATIC_CONFIRMED_RUNTIME
            else:
                return DetectionCategory.RUNTIME_ONLY
        
        # Check for static-only detection
        elif (detection_method in self.static_detection_methods or
              'static' in source_classification and 'runtime' not in source_classification):
            return DetectionCategory.STATIC_ONLY
        
        # Check for configuration-only detection
        elif (detection_method in self.config_detection_methods or
              'configuration' in source_classification or
              'manifest' in source_classification):
            return DetectionCategory.CONFIGURATION_ONLY
        
        # Check for hybrid detection
        elif ('hybrid' in source_classification or
              (self._has_runtime_indicators(vuln_data) and self._has_static_indicators(vuln_data))):
            return DetectionCategory.HYBRID_DETECTION
        
        # Default to unknown
        else:
            return DetectionCategory.UNKNOWN_CATEGORY
    
    def _extract_runtime_evidence_package(self, vuln_data: Dict[str, Any]) -> Optional[RuntimeEvidencePackage]:
        """Extract complete runtime evidence package."""
        
        # Check for runtime context
        runtime_context = vuln_data.get('runtime_context', {})
        
        # Direct runtime fields
        hook_timestamp = vuln_data.get('hook_timestamp') or (runtime_context.get('timestamp') if runtime_context else None)
        call_stack = vuln_data.get('stack_trace') or (runtime_context.get('stack_trace') if runtime_context else [])
        execution_context = vuln_data.get('execution_context') or (runtime_context.get('context') if runtime_context else {})
        runtime_parameters = vuln_data.get('runtime_parameters') or (runtime_context.get('parameters') if runtime_context else {})
        
        # Check if we have any runtime evidence
        if not any([hook_timestamp, call_stack, execution_context, runtime_parameters]):
            return None
        
        # Create Frida session info
        frida_session_info = {
            'session_id': vuln_data.get('frida_session_id') or (runtime_context.get('session_id') if runtime_context else None),
            'hook_name': vuln_data.get('hook_name') or (runtime_context.get('hook_name') if runtime_context else None),
            'plugin_name': vuln_data.get('plugin_name', 'unknown')
        }
        
        # Collection metadata
        collection_metadata = {
            'collection_timestamp': time.time(),
            'original_plugin': vuln_data.get('plugin_name', 'unknown'),
            'evidence_source': 'runtime_context_extraction',
            'validation_status': vuln_data.get('origin_validation', 'unknown')
        }
        
        return RuntimeEvidencePackage(
            hook_timestamp=hook_timestamp or time.time(),
            formatted_timestamp="",  # Will be calculated in __post_init__
            call_stack=call_stack if isinstance(call_stack, list) else [],
            execution_context=execution_context if isinstance(execution_context, dict) else {},
            runtime_parameters=runtime_parameters if isinstance(runtime_parameters, dict) else {},
            frida_session_info=frida_session_info,
            collection_metadata=collection_metadata
        )
    
    def _extract_static_evidence(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract static analysis evidence."""
        static_evidence = {}
        
        # Common static evidence fields
        static_fields = [
            'file_path', 'line_number', 'code_snippet', 'method_signature',
            'class_name', 'code_location', 'source_code', 'decompiled_code'
        ]
        
        for field in static_fields:
            if field in vuln_data and vuln_data[field] is not None:
                static_evidence[field] = vuln_data[field]
        
        return static_evidence
    
    def _extract_configuration_evidence(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration analysis evidence."""
        config_evidence = {}
        
        # Common configuration evidence fields
        config_fields = [
            'manifest_entry', 'permission', 'intent_filter', 'configuration_setting',
            'masvs_control', 'cwe_id'
        ]
        
        for field in config_fields:
            if field in vuln_data and vuln_data[field] is not None:
                config_evidence[field] = vuln_data[field]
        
        return config_evidence
    
    def _generate_actionable_information(self, vuln_data: Dict[str, Any], 
                                       detection_category: DetectionCategory) -> Dict[str, Any]:
        """Generate actionable debugging and remediation information."""
        
        actionable_info = {
            'debugging_guidance': [],
            'remediation_steps': [],
            'verification_methods': [],
            'additional_analysis': []
        }
        
        # Category-specific guidance
        if detection_category == DetectionCategory.RUNTIME_ONLY:
            actionable_info['debugging_guidance'] = [
                "This vulnerability was detected during runtime execution",
                "Check runtime logs and execution traces for more details",
                "Reproduce the issue by triggering the specific execution path"
            ]
            actionable_info['verification_methods'] = [
                "Re-run dynamic analysis to confirm detection",
                "Monitor application behavior during specific operations",
                "Use Frida to inspect runtime state"
            ]
        
        elif detection_category == DetectionCategory.STATIC_ONLY:
            actionable_info['debugging_guidance'] = [
                "This vulnerability was identified through static code analysis",
                "Review the source code at the specified location",
                "Check for similar patterns throughout the codebase"
            ]
            actionable_info['verification_methods'] = [
                "Manual code review at specified location",
                "Static analysis tool verification",
                "Code pattern search across entire codebase"
            ]
        
        elif detection_category == DetectionCategory.CONFIGURATION_ONLY:
            actionable_info['debugging_guidance'] = [
                "This issue was found in application configuration",
                "Review manifest files and configuration settings",
                "Check for security-related configuration problems"
            ]
            actionable_info['verification_methods'] = [
                "Manual manifest review",
                "Configuration security checklist",
                "Compliance verification against security standards"
            ]
        
        # Add general remediation guidance
        severity = vuln_data.get('severity', '').upper()
        if severity in ['HIGH', 'CRITICAL']:
            actionable_info['remediation_steps'].append("🚨 HIGH PRIORITY: Address this vulnerability immediately")
        
        # Add CWE-specific guidance if available
        cwe_id = vuln_data.get('cwe_id')
        if cwe_id:
            actionable_info['additional_analysis'].append(f"Review {cwe_id} guidelines for specific remediation advice")
        
        # Add MASVS control guidance if available
        masvs_control = vuln_data.get('masvs_control')
        if masvs_control:
            actionable_info['additional_analysis'].append(f"Verify compliance with {masvs_control}")
        
        return actionable_info
    
    def _calculate_categorization_confidence(self, vuln_data: Dict[str, Any]) -> float:
        """Calculate confidence score for categorization."""
        confidence = 0.0
        
        # Base confidence from classification
        classification_confidence = vuln_data.get('classification_confidence', 0.0)
        confidence += classification_confidence * 0.4
        
        # Evidence quality contribution
        if self._has_runtime_indicators(vuln_data):
            confidence += 0.3
        
        if self._has_static_indicators(vuln_data):
            confidence += 0.2
        
        # Detection method clarity
        detection_method = vuln_data.get('detection_method', '').lower()
        if detection_method and detection_method != 'unknown_method':
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _has_runtime_indicators(self, vuln_data: Dict[str, Any]) -> bool:
        """Check if vulnerability has runtime indicators."""
        return (
            vuln_data.get('runtime_context') is not None or
            vuln_data.get('hook_timestamp') is not None or
            vuln_data.get('stack_trace') is not None or
            vuln_data.get('execution_context') is not None or
            'runtime' in str(vuln_data.get('source', '')).lower()
        )
    
    def _has_static_indicators(self, vuln_data: Dict[str, Any]) -> bool:
        """Check if vulnerability has static analysis indicators."""
        return (
            vuln_data.get('source_code') is not None or
            vuln_data.get('decompiled_code') is not None or
            vuln_data.get('file_path') is not None or
            vuln_data.get('line_number') is not None or
            'static' in str(vuln_data.get('source', '')).lower()
        )
    
    def generate_detailed_report(self, categorized_vulnerabilities: Dict[str, List[FormattedVulnerability]]) -> Dict[str, Any]:
        """Generate detailed report with categorized vulnerabilities."""
        
        report = {
            'report_metadata': {
                'generation_timestamp': time.time(),
                'formatter_version': '1.0',
                'total_vulnerabilities': sum(len(vulns) for vulns in categorized_vulnerabilities.values())
            },
            'categorization_summary': {},
            'evidence_quality_summary': {},
            'detailed_findings': categorized_vulnerabilities,
            'actionable_insights': {}
        }
        
        # Generate categorization summary
        for category, vulns in categorized_vulnerabilities.items():
            report['categorization_summary'][category] = {
                'count': len(vulns),
                'percentage': (len(vulns) / report['report_metadata']['total_vulnerabilities'] * 100) if report['report_metadata']['total_vulnerabilities'] > 0 else 0,
                'severity_breakdown': self._analyze_severity_breakdown(vulns)
            }
        
        # Generate evidence quality summary
        all_vulns = [vuln for vulns in categorized_vulnerabilities.values() for vuln in vulns]
        report['evidence_quality_summary'] = self._analyze_evidence_quality(all_vulns)
        
        # Generate actionable insights
        report['actionable_insights'] = self._generate_report_insights(categorized_vulnerabilities)
        
        return report
    
    def _analyze_severity_breakdown(self, vulnerabilities: List[FormattedVulnerability]) -> Dict[str, int]:
        """Analyze severity breakdown for vulnerabilities."""
        severity_counts = {}
        
        for vuln in vulnerabilities:
            severity = vuln.severity.upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return severity_counts
    
    def _analyze_evidence_quality(self, vulnerabilities: List[FormattedVulnerability]) -> Dict[str, Any]:
        """Analyze evidence quality across all vulnerabilities."""
        
        quality_counts = {}
        runtime_evidence_count = 0
        
        for vuln in vulnerabilities:
            if vuln.runtime_evidence:
                quality = vuln.runtime_evidence.evidence_quality.value
                quality_counts[quality] = quality_counts.get(quality, 0) + 1
                runtime_evidence_count += 1
        
        return {
            'runtime_evidence_coverage': runtime_evidence_count / len(vulnerabilities) if vulnerabilities else 0,
            'quality_distribution': quality_counts,
            'total_with_runtime_evidence': runtime_evidence_count,
            'total_vulnerabilities': len(vulnerabilities)
        }
    
    def _generate_report_insights(self, categorized_vulnerabilities: Dict[str, List[FormattedVulnerability]]) -> Dict[str, Any]:
        """Generate actionable insights from categorized vulnerabilities."""
        
        insights = {
            'key_findings': [],
            'recommendations': [],
            'risk_assessment': {},
            'next_steps': []
        }
        
        # Analyze runtime-only findings
        runtime_only = categorized_vulnerabilities.get('runtime_only', [])
        if runtime_only:
            insights['key_findings'].append(f"🔍 {len(runtime_only)} vulnerabilities only detectable during runtime")
            insights['recommendations'].append("Prioritize runtime analysis for comprehensive security assessment")
        
        # Analyze static-confirmed runtime findings
        static_confirmed = categorized_vulnerabilities.get('static_confirmed_runtime', [])
        if static_confirmed:
            insights['key_findings'].append(f"✅ {len(static_confirmed)} static findings confirmed by runtime analysis")
            insights['recommendations'].append("Static analysis predictions validated by runtime execution")
        
        # Risk assessment
        total_vulns = sum(len(vulns) for vulns in categorized_vulnerabilities.values())
        high_severity = sum(1 for vulns in categorized_vulnerabilities.values() 
                          for vuln in vulns if vuln.severity in ['HIGH', 'CRITICAL'])
        
        insights['risk_assessment'] = {
            'total_vulnerabilities': total_vulns,
            'high_severity_count': high_severity,
            'risk_level': 'HIGH' if high_severity > 0 else 'MEDIUM' if total_vulns > 0 else 'LOW'
        }
        
        return insights


# Convenience functions
def format_runtime_vulnerability(vulnerability: Union[Dict[str, Any], Any]) -> FormattedVulnerability:
    """Format a single runtime vulnerability."""
    formatter = RuntimeEvidenceFormatter()
    return formatter.format_runtime_vulnerability(vulnerability)


def categorize_vulnerabilities_by_detection(vulnerabilities: List[Union[Dict[str, Any], Any]]) -> Dict[str, List[FormattedVulnerability]]:
    """Categorize vulnerabilities by detection method."""
    formatter = RuntimeEvidenceFormatter()
    return formatter.categorize_by_detection_method(vulnerabilities)


def generate_enhanced_vulnerability_report(vulnerabilities: List[Union[Dict[str, Any], Any]]) -> Dict[str, Any]:
    """Generate enhanced vulnerability report with categorization."""
    formatter = RuntimeEvidenceFormatter()
    categorized = formatter.categorize_by_detection_method(vulnerabilities)
    return formatter.generate_detailed_report(categorized)


if __name__ == "__main__":
    # Demo usage
    print("🎯 Runtime Evidence Formatter Demo")
    print("=" * 40)
    
    # Create formatter
    formatter = RuntimeEvidenceFormatter()
    
    print("✅ RuntimeEvidenceFormatter initialized")
    
    print("\n🔍 Detection Categories:")
    categories = list(DetectionCategory)
    for category in categories:
        print(f"   • {category.value}")
    
    print("\n📊 Evidence Quality Levels:")
    qualities = list(EvidenceQuality)
    for quality in qualities:
        print(f"   • {quality.value}")
    
    print("\n🎯 Formatting Features:")
    print("   ✅ Complete runtime evidence packaging")
    print("   ✅ Vulnerability categorization by detection method")
    print("   ✅ Evidence quality assessment")
    print("   ✅ Actionable debugging information")
    print("   ✅ Detailed reporting with insights")
    
    print("\n✅ Formatter ready for enhanced vulnerability reporting!")
