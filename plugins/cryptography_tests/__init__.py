#!/usr/bin/env python3
"""
Modularized Cryptography Tests Plugin for AODS

This module provides the entry point for the modularized cryptography analysis
plugin, coordinating between specialized analysis modules for optimal performance
and maintainability.

Architecture:
- crypto_analyzer.py: Core cryptographic implementation analysis
- nist_compliance_analyzer.py: NIST/FIPS compliance validation
- ssl_tls_analyzer.py: SSL/TLS security assessment
- key_management_analyzer.py: Key management analysis
- storage_analyzer.py: Cryptographic storage analysis
- advanced_crypto_analyzer.py: Advanced implementation analysis
- confidence_calculator.py: Crypto-specific confidence calculation
- formatters.py: output formatting
- data_structures.py: Standardized crypto vulnerability classes

External Configuration:
- crypto_patterns_config.yaml: External crypto security patterns (500+ patterns)
"""

import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from .crypto_analyzer import CryptoAnalyzer
from .nist_compliance_analyzer import NISTComplianceAnalyzer
from .ssl_tls_analyzer import SSLTLSAnalyzer
from .key_management_analyzer import KeyManagementAnalyzer
from .storage_analyzer import StorageAnalyzer
from .advanced_crypto_analyzer import AdvancedCryptoAnalyzer
from .confidence_calculator import CryptoConfidenceCalculator
from .formatters import CryptoAnalysisFormatter
from .data_structures import (
    CryptographicVulnerability,
    CryptographicImplementation,
    CryptographicAnalysis,
    KeyManagementAnalysis
)

logger = logging.getLogger(__name__)

__version__ = "2.0.0"
__author__ = "AODS Development Team"
__description__ = "Modularized Cryptography Analysis Plugin"

# Plugin characteristics for AODS discovery
PLUGIN_CHARACTERISTICS = {
    "mode": "safe",
    "requires_static": True,
    "requires_dynamic": False,
    "masvs_categories": [
        "MSTG-CRYPTO-1", "MSTG-CRYPTO-2", "MSTG-CRYPTO-3", 
        "MSTG-CRYPTO-4", "MSTG-CRYPTO-5", "MSTG-CRYPTO-6"
    ],
    "enterprise_ready": True,
    "description": "Comprehensive modular cryptographic security analysis",
    "modular_architecture": True,
    "performance_optimized": True,
    "professional_confidence": True
}

@dataclass
class AnalysisContext:
    """Analysis context for dependency injection."""
    apk_ctx: Any
    logger: logging.Logger
    config: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 120
    max_files: int = 500
    max_file_size_mb: int = 5

class CryptoAnalysisError(Exception):
    """Crypto analysis specific error with context."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.context = context or {}

class CryptographyTestsPlugin:
    """
    Main plugin entry point with dependency injection and modular orchestration.
    
    This class coordinates specialized analysis modules to provide comprehensive
    cryptographic security analysis with professional confidence calculation.
    """
    
    def __init__(self, apk_ctx: Any):
        """Initialize plugin with dependency injection."""
        self.apk_ctx = apk_ctx
        self.logger = logging.getLogger(__name__)
        
        # Create analysis context
        self.context = AnalysisContext(
            apk_ctx=apk_ctx,
            logger=self.logger,
            config=self._load_configuration(),
            timeout=120,
            max_files=500,
            max_file_size_mb=5
        )
        
        # Initialize modular components with dependency injection
        self.crypto_analyzer = CryptoAnalyzer(self.context)
        self.nist_analyzer = NISTComplianceAnalyzer(self.context)
        self.ssl_tls_analyzer = SSLTLSAnalyzer(self.context)
        self.key_mgmt_analyzer = KeyManagementAnalyzer(self.context)
        self.storage_analyzer = StorageAnalyzer(self.context)
        self.advanced_analyzer = AdvancedCryptoAnalyzer(self.context)
        self.confidence_calculator = CryptoConfidenceCalculator(self.context)
        self.formatter = CryptoAnalysisFormatter(self.context)
        
        self.logger.debug("Initialized CryptographyTestsPlugin with modular architecture")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load external configuration from YAML."""
        try:
            config_path = Path(__file__).parent / "crypto_patterns_config.yaml"
            if config_path.exists():
                import yaml
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
            return {}
        except Exception as e:
            self.logger.warning(f"Failed to load crypto patterns config: {e}")
            return {}
    
    def analyze(self) -> List[CryptographicVulnerability]:
        """
        Main analysis method with structured error handling.
        
        Orchestrates all specialized analyzers to provide comprehensive
        cryptographic security analysis with professional confidence.
        """
        try:
            analysis_start = time.time()
            self.logger.debug("Starting comprehensive cryptographic analysis")
            
            # Initialize findings collection
            all_findings = []
            
            # Execute core cryptographic analysis
            try:
                crypto_findings = self.crypto_analyzer.analyze()
                all_findings.extend(crypto_findings)
                self.logger.debug(f"Core crypto analysis: {len(crypto_findings)} findings")
            except Exception as e:
                self.logger.error(f"Core crypto analysis failed: {e}")
                raise CryptoAnalysisError("Core crypto analysis failure", {"error": str(e)})
            
            # Execute NIST compliance analysis
            try:
                nist_findings = self.nist_analyzer.analyze()
                all_findings.extend(nist_findings)
                self.logger.debug(f"NIST compliance analysis: {len(nist_findings)} findings")
            except Exception as e:
                self.logger.warning(f"NIST compliance analysis failed: {e}")
            
            # Execute SSL/TLS analysis
            try:
                ssl_findings = self.ssl_tls_analyzer.analyze()
                all_findings.extend(ssl_findings)
                self.logger.debug(f"SSL/TLS analysis: {len(ssl_findings)} findings")
            except Exception as e:
                self.logger.warning(f"SSL/TLS analysis failed: {e}")
            
            # Execute key management analysis
            try:
                key_findings = self.key_mgmt_analyzer.analyze()
                all_findings.extend(key_findings)
                self.logger.debug(f"Key management analysis: {len(key_findings)} findings")
            except Exception as e:
                self.logger.warning(f"Key management analysis failed: {e}")
            
            # Execute storage analysis
            try:
                storage_findings = self.storage_analyzer.analyze()
                all_findings.extend(storage_findings)
                self.logger.debug(f"Storage analysis: {len(storage_findings)} findings")
            except Exception as e:
                self.logger.warning(f"Storage analysis failed: {e}")
            
            # Execute advanced analysis
            try:
                advanced_findings = self.advanced_analyzer.analyze()
                all_findings.extend(advanced_findings)
                self.logger.debug(f"Advanced analysis: {len(advanced_findings)} findings")
            except Exception as e:
                self.logger.warning(f"Advanced analysis failed: {e}")
            
            # Apply professional confidence calculation
            self._apply_professional_confidence(all_findings)
            
            # Log analysis completion
            analysis_duration = time.time() - analysis_start
            self.logger.debug(f"Cryptographic analysis completed in {analysis_duration:.2f}s")
            self.logger.debug(f"Total findings: {len(all_findings)}")
            
            return all_findings
            
        except CryptoAnalysisError as e:
            self.logger.error(f"Crypto analysis failed: {e}", extra=e.context)
            raise
        except Exception as e:
            self.logger.error(f"Unexpected crypto analysis error: {e}")
            raise CryptoAnalysisError("Unexpected analysis failure") from e
    
    def _apply_professional_confidence(self, findings: List[CryptographicVulnerability]) -> None:
        """Apply professional confidence calculation to all findings."""
        try:
            for finding in findings:
                if hasattr(finding, 'confidence') and finding.confidence in [0.8, 0.9, 0.95, 0.7]:
                    # Replace hardcoded confidence with dynamic calculation
                    evidence = {
                        'pattern_type': finding.type,
                        'algorithm': getattr(finding, 'algorithm', 'unknown'),
                        'severity': finding.severity,
                        'location': finding.location,
                        'implementation_context': 'production'
                    }
                    finding.confidence = self.confidence_calculator.calculate_crypto_confidence(
                        vulnerability=finding,
                        evidence=evidence
                    )
        except Exception as e:
            self.logger.warning(f"Failed to apply professional confidence: {e}")
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary."""
        return {
            "plugin_version": __version__,
            "modular_architecture": True,
            "professional_confidence": True,
            "components_loaded": [
                "CryptoAnalyzer",
                "NISTComplianceAnalyzer", 
                "SSLTLSAnalyzer",
                "KeyManagementAnalyzer",
                "StorageAnalyzer",
                "AdvancedCryptoAnalyzer",
                "CryptoConfidenceCalculator",
                "CryptoAnalysisFormatter"
            ],
            "external_patterns_loaded": len(self.context.config.get('patterns', {})),
            "analysis_timeout": self.context.timeout,
            "max_files": self.context.max_files,
            "max_file_size_mb": self.context.max_file_size_mb
        }

# Main plugin entry point for AODS discovery
def analyze_cryptography_security(apk_ctx: Any) -> List[CryptographicVulnerability]:
    """
    Main entry point for cryptographic security analysis.
    
    This function maintains backward compatibility while providing
    modular architecture and professional confidence calculation.
    """
    try:
        plugin = CryptographyTestsPlugin(apk_ctx)
        return plugin.analyze()
    except Exception as e:
        logger.error(f"Cryptography analysis failed: {e}")
        return []

# Export main interface
__all__ = [
    'CryptographyTestsPlugin',
    'AnalysisContext',
    'CryptographicAnalysis',
    'CryptographicVulnerability',
    'CryptographicImplementation',
    'KeyManagementAnalysis',
    'CryptoAnalyzer',
    'NISTComplianceAnalyzer',
    'SSLTLSAnalyzer',
    'KeyManagementAnalyzer',
    'StorageAnalyzer',
    'AdvancedCryptoAnalyzer',
    'CryptoConfidenceCalculator',
    'CryptoAnalysisFormatter',
    'CryptoAnalysisError',
    'analyze_cryptography_security',
    'run'
]

# Plugin compatibility function
def run(apk_ctx):
    """
    Main plugin entry point for compatibility with plugin manager.
    
    Args:
        apk_ctx: APK context object
        
    Returns:
        Tuple of (plugin_name, result)
    """
    try:
        from rich.text import Text
        
        # Initialize and run plugin
        plugin = CryptographyTestsPlugin(apk_ctx)
        result = plugin.analyze()
        
        if result and hasattr(result, 'vulnerabilities') and result.vulnerabilities:
            finding_count = len(result.vulnerabilities)
            critical_count = sum(1 for v in result.vulnerabilities if hasattr(v, 'severity') and v.severity in ['CRITICAL', 'HIGH'])
            
            if critical_count > 0:
                status_text = Text(f"Found {finding_count} crypto issues ({critical_count} critical/high)", style="red")
            elif finding_count > 0:
                status_text = Text(f"Found {finding_count} crypto issues", style="yellow")
            else:
                status_text = Text("No crypto vulnerabilities detected", style="green")
        else:
            status_text = Text("Cryptography analysis completed", style="blue")
        
        return "Cryptography Tests", status_text
        
    except Exception as e:
        from rich.text import Text
        return "Cryptography Tests", Text(f"Analysis failed: {str(e)}", style="red") 