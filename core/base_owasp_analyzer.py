#!/usr/bin/env python3
"""
Base OWASP Analyzer Interface
Standard interface for all MASVS analyzers to ensure consistent method signatures and return types.

This module defines the base interface that all OWASP MASVS analyzers must implement
to ensure consistent method signatures, return types, and integration compatibility.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class SecurityFinding:
    """Standard security finding representation across all analyzers."""

    finding_id: str
    finding_type: str
    severity: str
    confidence: float
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    pattern_matched: Optional[str] = None
    category: str = ""
    remediation: str = ""
    context: Dict[str, Any] = None
    masvs_category: str = ""
    mastg_test_id: str = ""

    def __post_init__(self):
        if self.context is None:
            self.context = {}

@dataclass
class StandardAnalysisResult:
    """Standard analysis result structure for all OWASP analyzers."""

    apk_path: str
    analyzer_name: str
    analysis_time: float
    findings: List[SecurityFinding]
    statistics: Dict[str, Any]
    masvs_category: str
    mastg_tests_executed: List[str] = None
    error_message: Optional[str] = None

    def __post_init__(self):
        if self.mastg_tests_executed is None:
            self.mastg_tests_executed = []

    @property
    def security_findings(self) -> List[SecurityFinding]:
        """Alias for findings to maintain compatibility with evaluation scripts."""
        return self.findings

    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def high_severity_count(self) -> int:
        """Number of high severity findings."""
        return len([f for f in self.findings if f.severity.upper() == "HIGH"])

    @property
    def medium_severity_count(self) -> int:
        """Number of medium severity findings."""
        return len([f for f in self.findings if f.severity.upper() == "MEDIUM"])

    @property
    def low_severity_count(self) -> int:
        """Number of low severity findings."""
        return len([f for f in self.findings if f.severity.upper() == "LOW"])

class BaseOWASPAnalyzer(ABC):
    """
    Abstract base class for all OWASP MASVS analyzers.

    All analyzer implementations must inherit from this class and implement
    the analyze_apk method to ensure consistent integration.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the analyzer with optional configuration."""
        self.config = config or {}
        self.analyzer_name = self.__class__.__name__
        self.masvs_category = self._get_masvs_category()

    @abstractmethod
    def analyze_apk(self, apk_path: str) -> StandardAnalysisResult:
        """
        Analyze an APK file for security vulnerabilities.

        This is the standard method signature that all analyzers must implement.

        Args:
            apk_path: Path to the APK file to analyze

        Returns:
            StandardAnalysisResult containing all findings and metadata
        """
        # Default implementation - should be overridden by subclasses
        raise NotImplementedError("Subclasses must implement run_analysis method")

    @abstractmethod
    def _get_masvs_category(self) -> str:
        """Return the MASVS category this analyzer implements."""
        # Default implementation - should be overridden by subclasses
        raise NotImplementedError("Subclasses must implement _get_masvs_category method")

    def _create_finding(
        self,
        finding_type: str,
        severity: str,
        title: str,
        description: str,
        confidence: float = 0.8,
        **kwargs,
    ) -> SecurityFinding:
        """
        Helper method to create standardized security findings.

        Args:
            finding_type: Type of security finding
            severity: Severity level (HIGH, MEDIUM, LOW)
            title: Short title describing the finding
            description: Detailed description of the vulnerability
            confidence: Confidence level (0.0 to 1.0)
            **kwargs: Additional fields for the SecurityFinding

        Returns:
            SecurityFinding instance
        """
        finding_id = f"{self.analyzer_name}_{int(time.time() * 1000000)}"

        return SecurityFinding(
            finding_id=finding_id,
            finding_type=finding_type,
            severity=severity.upper(),
            confidence=confidence,
            title=title,
            description=description,
            masvs_category=self.masvs_category,
            **kwargs,
        )

    def _create_result(
        self,
        apk_path: str,
        analysis_time: float,
        findings: List[SecurityFinding],
        statistics: Dict[str, Any],
        mastg_tests: List[str] = None,
        error_message: Optional[str] = None,
    ) -> StandardAnalysisResult:
        """
        Helper method to create standardized analysis results.

        Args:
            apk_path: Path to analyzed APK
            analysis_time: Time taken for analysis
            findings: List of security findings
            statistics: Analysis statistics
            mastg_tests: List of MASTG test IDs executed
            error_message: Error message if analysis failed

        Returns:
            StandardAnalysisResult instance
        """
        return StandardAnalysisResult(
            apk_path=apk_path,
            analyzer_name=self.analyzer_name,
            analysis_time=analysis_time,
            findings=findings,
            statistics=statistics,
            masvs_category=self.masvs_category,
            mastg_tests_executed=mastg_tests or [],
            error_message=error_message,
        )

    def validate_apk_path(self, apk_path: str) -> bool:
        """
        Validate that the APK path exists and is readable.

        Args:
            apk_path: Path to APK file

        Returns:
            True if valid, False otherwise
        """
        import os

        if not os.path.exists(apk_path):
            return False

        if not os.path.isfile(apk_path):
            return False

        if not apk_path.lower().endswith(".apk"):
            return False

        return True

    def get_analyzer_info(self) -> Dict[str, Any]:
        """
        Get information about this analyzer.

        Returns:
            Dictionary containing analyzer metadata
        """
        return {
            "name": self.analyzer_name,
            "masvs_category": self.masvs_category,
            "config": self.config,
        }

class AnalyzerRegistry:
    """Registry for managing all OWASP analyzers."""

    def __init__(self):
        self._analyzers: Dict[str, BaseOWASPAnalyzer] = {}

    def register(self, analyzer: BaseOWASPAnalyzer):
        """Register an analyzer instance."""
        self._analyzers[analyzer.masvs_category] = analyzer

    def get_analyzer(self, masvs_category: str) -> Optional[BaseOWASPAnalyzer]:
        """Get analyzer by MASVS category."""
        return self._analyzers.get(masvs_category)

    def get_all_analyzers(self) -> Dict[str, BaseOWASPAnalyzer]:
        """Get all registered analyzers."""
        return self._analyzers.copy()

    def analyze_with_all(self, apk_path: str) -> Dict[str, StandardAnalysisResult]:
        """
        Analyze APK with all registered analyzers.

        Args:
            apk_path: Path to APK file

        Returns:
            Dictionary mapping MASVS category to analysis results
        """
        results = {}

        for category, analyzer in self._analyzers.items():
            try:
                result = analyzer.analyze_apk(apk_path)
                results[category] = result
            except Exception as e:
                # Create error result for failed analysis
                results[category] = StandardAnalysisResult(
                    apk_path=apk_path,
                    analyzer_name=analyzer.analyzer_name,
                    analysis_time=0.0,
                    findings=[],
                    statistics={"error": str(e)},
                    masvs_category=category,
                    error_message=str(e),
                )

        return results

# Global analyzer registry instance
analyzer_registry = AnalyzerRegistry()
