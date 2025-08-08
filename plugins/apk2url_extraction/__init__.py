#!/usr/bin/env python3
"""
APK2URL Extraction Plugin - Main Orchestration Module

Main plugin orchestration with dependency injection pattern.
Integrates URL extractor, pattern analyzer, noise filter, confidence calculator,
and security assessor for comprehensive endpoint discovery and risk assessment.
"""

import logging
import yaml
import time
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
from rich.text import Text

from core.apk_ctx import APKContext

from .data_structures import (
    ExtractionResults, ExtractionContext, SecurityAssessment,
    EndpointFinding, SecurityRisk, FindingsDict
)
from .url_extractor import URLExtractor
from .pattern_analyzer import PatternAnalyzer
from .noise_filter import NoiseFilter
from .confidence_calculator import APK2URLConfidenceCalculator
from .security_assessor import SecurityAssessor

logger = logging.getLogger(__name__)

class APK2URLExtractionPlugin:
    """
    Main APK2URL extraction plugin with modular architecture.
    
    Orchestrates comprehensive endpoint discovery using dependency injection
    pattern with modular components for extraction, analysis, and assessment.
    """
    
    PLUGIN_VERSION = "2.0.0"
    
    def __init__(self, apk_ctx: APKContext):
        """Initialize plugin with APK context and dependency injection."""
        self.apk_ctx = apk_ctx
        self.apk_path = Path(apk_ctx.apk_path)
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Initialize components with dependency injection
        self.url_extractor = self._create_url_extractor()
        self.pattern_analyzer = self._create_pattern_analyzer()
        self.noise_filter = self._create_noise_filter()
        self.confidence_calculator = self._create_confidence_calculator()
        self.security_assessor = self._create_security_assessor()
        
        # Analysis results
        self.extraction_results: Optional[ExtractionResults] = None
        self.security_assessment: Optional[SecurityAssessment] = None
        
        logger.debug(f"Initialized APK2URLExtractionPlugin for {self.apk_path}")
    
    def analyze(self) -> Tuple[str, Union[str, Text]]:
        """
        Perform comprehensive APK2URL endpoint extraction and analysis.
        
        Returns:
            Tuple of (test_name, formatted_results)
        """
        try:
            logger.debug("Starting APK2URL extraction and analysis")
            start_time = time.time()
            
            # Step 1: Extract endpoints using URL extractor
            self.extraction_results = self.url_extractor.extract_endpoints()
            
            # Step 2: Perform security assessment
            self.security_assessment = self.security_assessor.assess_security(
                self.extraction_results
            )
            
            # Step 3: Cache results for other plugins
            self._cache_results()
            
            # Step 4: Generate formatted report
            formatted_report = self._generate_formatted_report()
            
            analysis_duration = time.time() - start_time
            logger.debug(f"APK2URL analysis completed in {analysis_duration:.2f}s")
            
            return ("APK2URL Endpoint Discovery", formatted_report)
            
        except Exception as e:
            logger.error(f"Error during APK2URL analysis: {e}")
            error_report = self._generate_error_report(str(e))
            return ("APK2URL Endpoint Discovery", error_report)
    
    def _create_url_extractor(self) -> URLExtractor:
        """Create URL extractor with dependency injection."""
        return URLExtractor(self.apk_path, self.config, self.PLUGIN_VERSION)
    
    def _create_pattern_analyzer(self) -> PatternAnalyzer:
        """Create pattern analyzer with dependency injection."""
        return PatternAnalyzer(self.config)
    
    def _create_noise_filter(self) -> NoiseFilter:
        """Create noise filter with dependency injection."""
        return NoiseFilter(self.config)
    
    def _create_confidence_calculator(self) -> APK2URLConfidenceCalculator:
        """Create confidence calculator with dependency injection."""
        return APK2URLConfidenceCalculator()
    
    def _create_security_assessor(self) -> SecurityAssessor:
        """Create security assessor with dependency injection."""
        return SecurityAssessor(self.config)
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            config_path = Path(__file__).parent / "extraction_patterns_config.yaml"
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.debug(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            logger.warning(f"Error loading configuration: {e}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration if file loading fails."""
        return {
            'url_patterns': {
                'standard_http': {
                    'pattern': r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\"\'<>]*)?',
                    'confidence': 0.95
                }
            },
            'processing_limits': {
                'max_file_size_mb': 50,
                'max_dex_files': 5,
                'max_processing_time': 300
            },
            'security_thresholds': {
                'critical_risk_threshold': 1,
                'high_risk_threshold': 3,
                'medium_risk_threshold': 5
            }
        }
    
    def _cache_results(self) -> None:
        """Cache results for other plugins."""
        if self.extraction_results:
            # Convert to legacy format for compatibility
            legacy_findings = {
                'urls': self.extraction_results.urls,
                'ips': self.extraction_results.ips,
                'domains': self.extraction_results.domains,
                'api_endpoints': self.extraction_results.api_endpoints,
                'deep_links': self.extraction_results.deep_links,
                'file_urls': self.extraction_results.file_urls,
                'certificates': self.extraction_results.certificates,
                'secrets': self.extraction_results.secrets
            }
            
            self.apk_ctx.set_cache("apk2url_findings", legacy_findings)
            self.apk_ctx.set_cache("apk2url_detailed_results", self.extraction_results)
            self.apk_ctx.set_cache("apk2url_security_assessment", self.security_assessment)
    
    def _generate_formatted_report(self) -> Text:
        """Generate comprehensive formatted report using Rich."""
        report = Text()
        
        # Header
        report.append("🌐 APK2URL Endpoint Discovery Analysis\n", style="bold blue")
        report.append("=" * 70 + "\n\n", style="blue")
        
        if not self.extraction_results:
            report.append("❌ No extraction results available\n", style="red")
            return report
        
        # Summary statistics
        total_findings = sum(len(category) for category in [
            self.extraction_results.urls,
            self.extraction_results.ips,
            self.extraction_results.domains,
            self.extraction_results.api_endpoints,
            self.extraction_results.deep_links,
            self.extraction_results.file_urls,
            self.extraction_results.certificates,
            self.extraction_results.secrets
        ])
        
        report.append(f"📊 Total Endpoints Discovered: {total_findings}\n", style="bold green")
        
        # Performance statistics
        if self.extraction_results.statistics:
            stats = self.extraction_results.statistics
            report.append(f"⏱️ Analysis Duration: {stats.extraction_duration:.2f}s\n", style="cyan")
            report.append(f"📁 Files Processed: {stats.total_files_processed}\n", style="cyan")
            report.append(f"🔍 Unique Endpoints: {stats.unique_endpoints}\n", style="cyan")
            report.append(f"🚫 Noise Filtered: {stats.noise_filtered}\n", style="yellow")
        
        report.append("\n")
        
        # Security assessment
        if self.security_assessment:
            self._add_security_assessment_to_report(report)
        
        # Findings by category
        self._add_findings_to_report(report)
        
        # Recommendations
        if self.security_assessment and self.security_assessment.recommendations:
            self._add_recommendations_to_report(report)
        
        return report
    
    def _add_security_assessment_to_report(self, report: Text) -> None:
        """Add security assessment section to report."""
        assessment = self.security_assessment
        
        report.append("🛡️ Security Risk Assessment\n", style="bold red")
        report.append("-" * 30 + "\n", style="red")
        
        # Overall risk
        risk_color = self._get_risk_color(assessment.overall_risk)
        report.append(f"Overall Risk Level: {assessment.overall_risk.value.upper()}\n", 
                     style=f"bold {risk_color}")
        report.append(f"Risk Score: {assessment.risk_score:.2f}/1.0\n", style=risk_color)
        
        # Risk distribution
        if assessment.critical_findings > 0:
            report.append(f"❌ Critical Findings: {assessment.critical_findings}\n", style="red")
        if assessment.high_risk_findings > 0:
            report.append(f"⚠️ High Risk Findings: {assessment.high_risk_findings}\n", style="bright_red")
        if assessment.medium_risk_findings > 0:
            report.append(f"🟡 Medium Risk Findings: {assessment.medium_risk_findings}\n", style="yellow")
        if assessment.low_risk_findings > 0:
            report.append(f"🟢 Low Risk Findings: {assessment.low_risk_findings}\n", style="green")
        if assessment.info_findings > 0:
            report.append(f"ℹ️ Informational Findings: {assessment.info_findings}\n", style="blue")
        
        # Specific security concerns
        concerns = []
        if assessment.cleartext_communications > 0:
            concerns.append(f"🔓 {assessment.cleartext_communications} cleartext communications")
        if assessment.hardcoded_credentials > 0:
            concerns.append(f"🔑 {assessment.hardcoded_credentials} hardcoded credentials")
        if assessment.development_endpoints > 0:
            concerns.append(f"🧪 {assessment.development_endpoints} development endpoints")
        if assessment.suspicious_domains > 0:
            concerns.append(f"⚠️ {assessment.suspicious_domains} suspicious domains")
        
        if concerns:
            report.append("\nSpecific Security Concerns:\n", style="bold yellow")
            for concern in concerns:
                report.append(f"  • {concern}\n", style="yellow")
        
        report.append("\n")
    
    def _add_findings_to_report(self, report: Text) -> None:
        """Add findings section to report."""
        categories = [
            ("🔑 Secrets Found", self.extraction_results.secrets, "bright_red"),
            ("🌍 URLs", self.extraction_results.urls, "green"),
            ("🔗 API Endpoints", self.extraction_results.api_endpoints, "magenta"),
            ("🖥️ IP Addresses", self.extraction_results.ips, "yellow"),
            ("🌐 Domains", self.extraction_results.domains, "cyan"),
            ("📱 Deep Links", self.extraction_results.deep_links, "blue"),
            ("📁 File URLs", self.extraction_results.file_urls, "bright_blue"),
            ("🔒 Certificates", self.extraction_results.certificates, "white")
        ]
        
        for title, items, color in categories:
            if items:
                report.append(f"{title} ({len(items)})\n", style=f"bold {color}")
                
                # Display items (limit to 20 to avoid overwhelming output)
                displayed_items = list(items)[:20]
                for item in displayed_items:
                    # Truncate very long items
                    display_item = item if len(item) <= 80 else f"{item[:77]}..."
                    report.append(f"  • {display_item}\n", style=color)
                
                if len(items) > 20:
                    report.append(f"  ... and {len(items) - 20} more items\n", 
                                style=f"dim {color}")
                
                report.append("\n")
            else:
                report.append(f"{title}: None found\n", style=f"dim {color}")
    
    def _add_recommendations_to_report(self, report: Text) -> None:
        """Add recommendations section to report."""
        report.append("💡 Security Recommendations\n", style="bold yellow")
        report.append("-" * 30 + "\n", style="yellow")
        
        for i, recommendation in enumerate(self.security_assessment.recommendations, 1):
            # Color code by priority
            if recommendation.startswith("CRITICAL"):
                style = "red"
            elif recommendation.startswith("HIGH"):
                style = "bright_red"
            elif recommendation.startswith("MEDIUM"):
                style = "yellow"
            else:
                style = "white"
            
            report.append(f"{i}. {recommendation}\n", style=style)
        
        # MASVS compliance notes
        if self.security_assessment.compliance_notes:
            report.append("\n📋 MASVS Compliance Notes\n", style="bold blue")
            report.append("-" * 30 + "\n", style="blue")
            for note in self.security_assessment.compliance_notes:
                report.append(f"  • {note}\n", style="blue")
        
        report.append("\n")
    
    def _generate_error_report(self, error_message: str) -> Text:
        """Generate error report."""
        report = Text()
        report.append("🌐 APK2URL Endpoint Discovery Analysis\n", style="bold blue")
        report.append("=" * 70 + "\n\n", style="blue")
        report.append("❌ Analysis Failed\n", style="bold red")
        report.append(f"Error: {error_message}\n", style="red")
        report.append("\n💡 Troubleshooting Tips:\n", style="bold yellow")
        report.append("  • Ensure APK file is valid and accessible\n", style="yellow")
        report.append("  • Check available disk space and memory\n", style="yellow")
        report.append("  • Try with a smaller APK file\n", style="yellow")
        return report
    
    def _get_risk_color(self, risk: SecurityRisk) -> str:
        """Get color for risk level."""
        risk_colors = {
            SecurityRisk.CRITICAL: "red",
            SecurityRisk.HIGH: "bright_red",
            SecurityRisk.MEDIUM: "yellow",
            SecurityRisk.LOW: "green",
            SecurityRisk.INFO: "blue"
        }
        return risk_colors.get(risk, "white")
    
    def get_findings_dict(self) -> Optional[FindingsDict]:
        """Get findings in legacy dictionary format."""
        if not self.extraction_results:
            return None
        
        return {
            'urls': self.extraction_results.urls,
            'ips': self.extraction_results.ips,
            'domains': self.extraction_results.domains,
            'api_endpoints': self.extraction_results.api_endpoints,
            'deep_links': self.extraction_results.deep_links,
            'file_urls': self.extraction_results.file_urls,
            'certificates': self.extraction_results.certificates,
            'secrets': self.extraction_results.secrets
        }
    
    def get_detailed_results(self) -> Optional[ExtractionResults]:
        """Get detailed extraction results."""
        return self.extraction_results
    
    def get_security_assessment(self) -> Optional[SecurityAssessment]:
        """Get security assessment results."""
        return self.security_assessment
    
    def get_analysis_metadata(self) -> Dict[str, Any]:
        """Get analysis metadata and statistics."""
        metadata = {
            'plugin_version': self.PLUGIN_VERSION,
            'modular_architecture': True,
            'analysis_timestamp': time.time()
        }
        
        if self.extraction_results and self.extraction_results.statistics:
            stats = self.extraction_results.statistics
            metadata.update({
                'extraction_duration': stats.extraction_duration,
                'files_processed': stats.total_files_processed,
                'unique_endpoints': stats.unique_endpoints,
                'noise_filtered': stats.noise_filtered,
                'processing_errors': stats.processing_errors
            })
        
        if self.security_assessment:
            metadata.update({
                'overall_risk': self.security_assessment.overall_risk.value,
                'risk_score': self.security_assessment.risk_score,
                'mitigation_priority': self.security_assessment.mitigation_priority
            })
        
        return metadata

# Legacy compatibility functions for plugin manager
def run(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """
    Main plugin entry point with legacy compatibility.
    
    Args:
        apk_ctx: APK context instance
        
    Returns:
        Tuple of (test_name, formatted_results)
    """
    plugin = APK2URLExtractionPlugin(apk_ctx)
    return plugin.analyze()

def run_plugin(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """
    Plugin interface function expected by the plugin manager.
    
    Args:
        apk_ctx: APK context instance
        
    Returns:
        Tuple of (test_name, formatted_results)
    """
    return run(apk_ctx)

def run_apk2url_extraction(apk_ctx: APKContext) -> Tuple[str, Text]:
    """
    Standalone function to run APK2URL extraction.
    
    Args:
        apk_ctx: APK context instance
        
    Returns:
        Tuple of test name and Rich Text results
    """
    result = run(apk_ctx)
    return (result[0], result[1] if isinstance(result[1], Text) else Text(str(result[1])))

# Plugin metadata for framework discovery
PLUGIN_INFO = {
    "name": "APK2URL Endpoint Discovery",
    "description": "Comprehensive URL, IP address, and endpoint extraction from APK files with advanced pattern matching",
    "version": APK2URLExtractionPlugin.PLUGIN_VERSION,
    "architecture": "modular",
    "masvs_controls": ["MSTG-NETWORK-01", "MSTG-NETWORK-02", "MSTG-PLATFORM-03", "MSTG-CRYPTO-01"],
    "risk_level": "MEDIUM",
    "analysis_mode": "safe",
    "category": "network"
} 