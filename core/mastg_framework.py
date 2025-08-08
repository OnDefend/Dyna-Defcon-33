"""
OWASP MASTG (Mobile Application Security Testing Guide) Framework

This framework provides MASTG test case management and execution
for mobile application security testing. It includes:
- Structured test case definitions following MASTG methodology
- MASVS compliance mapping and validation
- Test execution engine with result aggregation
- Technical reporting with MASTG alignment
- Risk assessment and remediation guidance

MASVS Controls Integration:
- All MASVS v1.5.0 categories and controls
- MASTG test case mapping
- CWE and OWASP Top 10 Mobile alignment
"""

import datetime
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.text import Text

from core.apk_ctx import APKContext

class MASTGCategory(Enum):
    """MASTG test categories following OWASP classification."""

    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    PLATFORM_INTERACTION = "platform_interaction"
    DATA_STORAGE = "data_storage"
    CRYPTOGRAPHY = "cryptography"
    AUTHENTICATION = "authentication"
    NETWORK_COMMUNICATION = "network_communication"
    PLATFORM_APIS = "platform_apis"
    CODE_QUALITY = "code_quality"
    TAMPERING_REVERSE_ENGINEERING = "tampering_reverse_engineering"

class MASVSLevel(Enum):
    """MASVS verification levels."""

    L1 = "L1"  # Standard security
    L2 = "L2"  # Defense in depth
    R = "R"  # Resiliency against reverse engineering

class TestResult(Enum):
    """Test execution results."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIP = "SKIP"
    ERROR = "ERROR"

@dataclass
class MASTGTestCase:
    """Individual MASTG test case definition."""

    test_id: str
    title: str
    description: str
    category: MASTGCategory
    masvs_controls: List[str]
    masvs_level: MASVSLevel
    cwe_ids: List[str] = field(default_factory=list)
    owasp_mobile_refs: List[str] = field(default_factory=list)
    automated: bool = True
    manual_steps: List[str] = field(default_factory=list)
    tools_required: List[str] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)
    remediation_refs: List[str] = field(default_factory=list)

@dataclass
class TestExecution:
    """Test execution record with results and evidence."""

    test_case: MASTGTestCase
    result: TestResult
    execution_time: datetime.datetime
    evidence: List[str] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    risk_level: str = "UNKNOWN"

class MASTGTestExecutor(ABC):
    """Abstract base class for MASTG test executors."""

    @abstractmethod
    def execute(self, apk_ctx: APKContext, test_case: MASTGTestCase) -> TestExecution:
        """Execute a specific MASTG test case."""
        pass

    @abstractmethod
    def is_applicable(self, apk_ctx: APKContext, test_case: MASTGTestCase) -> bool:
        """Determine if test case is applicable to the given APK."""
        pass

class MASTGFramework:
    """Main MASTG testing framework."""

    def __init__(self):
        """Initialize the MASTG framework."""
        self.test_cases: Dict[str, MASTGTestCase] = {}
        self.executors: Dict[str, MASTGTestExecutor] = {}
        self.execution_history: List[TestExecution] = []
        self.console = Console()

        # Initialize default test cases
        self._initialize_default_tests()

    def register_test_case(self, test_case: MASTGTestCase) -> None:
        """Register a new MASTG test case."""
        self.test_cases[test_case.test_id] = test_case
        logging.info(f"Registered MASTG test case: {test_case.test_id}")

    def register_executor(self, test_id: str, executor: MASTGTestExecutor) -> None:
        """Register an executor for a specific test case."""
        self.executors[test_id] = executor
        logging.info(f"Registered executor for test: {test_id}")

    def get_applicable_tests(
        self,
        apk_ctx: APKContext,
        categories: Optional[List[MASTGCategory]] = None,
        masvs_level: Optional[MASVSLevel] = None,
    ) -> List[MASTGTestCase]:
        """Get list of applicable tests for given APK context and filters."""
        applicable_tests = []

        for test_case in self.test_cases.values():
            # Filter by category
            if categories and test_case.category not in categories:
                continue

            # Filter by MASVS level
            if masvs_level and test_case.masvs_level != masvs_level:
                continue

            # Check if test is applicable using executor
            executor = self.executors.get(test_case.test_id)
            if executor and executor.is_applicable(apk_ctx, test_case):
                applicable_tests.append(test_case)
            elif not executor and test_case.automated:
                # Test case exists but no executor - mark for manual testing
                applicable_tests.append(test_case)

        return applicable_tests

    def execute_test_suite(
        self,
        apk_ctx: APKContext,
        test_cases: Optional[List[MASTGTestCase]] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[TestExecution]:
        """Execute a suite of MASTG tests."""
        if test_cases is None:
            test_cases = list(self.test_cases.values())

        executions = []

        with Progress() as progress:
            task = progress.add_task("Executing MASTG tests...", total=len(test_cases))

            for test_case in test_cases:
                try:
                    execution = self._execute_single_test(apk_ctx, test_case)
                    executions.append(execution)
                    self.execution_history.append(execution)

                    if progress_callback:
                        progress_callback(execution)

                except Exception as e:
                    logging.error(f"Error executing test {test_case.test_id}: {e}")
                    error_execution = TestExecution(
                        test_case=test_case,
                        result=TestResult.ERROR,
                        execution_time=datetime.datetime.now(),
                        error_message=str(e),
                    )
                    executions.append(error_execution)
                    self.execution_history.append(error_execution)

                progress.update(task, advance=1)

        return executions

    def _execute_single_test(
        self, apk_ctx: APKContext, test_case: MASTGTestCase
    ) -> TestExecution:
        """Execute a single MASTG test case."""
        executor = self.executors.get(test_case.test_id)

        if not executor:
            # No automated executor available
            return TestExecution(
                test_case=test_case,
                result=TestResult.SKIP,
                execution_time=datetime.datetime.now(),
                error_message="No automated executor available - manual testing required",
            )

        if not executor.is_applicable(apk_ctx, test_case):
            return TestExecution(
                test_case=test_case,
                result=TestResult.SKIP,
                execution_time=datetime.datetime.now(),
                error_message="Test not applicable to this APK",
            )

        return executor.execute(apk_ctx, test_case)

    def generate_compliance_report(self, executions: List[TestExecution]) -> Text:
        """Generate comprehensive MASTG compliance report."""
        report = Text()

        # Header
        report.append("🛡️ OWASP MASTG Compliance Report\n", style="bold blue")
        report.append("=" * 70 + "\n\n", style="blue")

        # Executive summary
        total_tests = len(executions)
        passed_tests = len([e for e in executions if e.result == TestResult.PASS])
        failed_tests = len([e for e in executions if e.result == TestResult.FAIL])
        warning_tests = len([e for e in executions if e.result == TestResult.WARNING])
        skipped_tests = len([e for e in executions if e.result == TestResult.SKIP])
        error_tests = len([e for e in executions if e.result == TestResult.ERROR])

        # Overall compliance score
        compliance_score = (
            passed_tests / max(total_tests - skipped_tests - error_tests, 1)
        ) * 100

        report.append("📊 Executive Summary\n", style="bold green")
        report.append(f"Total Tests: {total_tests}\n")
        report.append(f"Passed: {passed_tests} ✅\n", style="green")
        report.append(f"Failed: {failed_tests} ❌\n", style="red")
        report.append(f"Warnings: {warning_tests} ⚠️\n", style="yellow")
        report.append(f"Skipped: {skipped_tests} ⏭️\n", style="dim")
        report.append(f"Errors: {error_tests} 🚨\n", style="bright_red")

        # Compliance score with color coding
        score_color = (
            "green"
            if compliance_score >= 90
            else "yellow" if compliance_score >= 70 else "red"
        )
        report.append(
            f"Compliance Score: {compliance_score:.1f}%\n\n",
            style=f"bold {score_color}",
        )

        # MASVS compliance breakdown
        report.append("🔍 MASVS Control Compliance\n", style="bold cyan")
        masvs_controls = {}

        for execution in executions:
            for control in execution.test_case.masvs_controls:
                if control not in masvs_controls:
                    masvs_controls[control] = {"total": 0, "passed": 0, "failed": 0}

                masvs_controls[control]["total"] += 1
                if execution.result == TestResult.PASS:
                    masvs_controls[control]["passed"] += 1
                elif execution.result == TestResult.FAIL:
                    masvs_controls[control]["failed"] += 1

        # Display MASVS compliance as formatted text instead of table
        if masvs_controls:
            for control, stats in sorted(masvs_controls.items()):
                total = stats["total"]
                passed = stats["passed"]
                failed = stats["failed"]
                compliance = (passed / max(total, 1)) * 100

                compliance_style = (
                    "green"
                    if compliance >= 90
                    else "yellow" if compliance >= 70 else "red"
                )

                report.append(
                    f"  {control}: {compliance:.1f}% ({passed}/{total} passed, {failed} failed)\n",
                    style=compliance_style,
                )
        else:
            report.append("  No MASVS controls tested\n", style="dim")

        report.append("\n")

        # Category analysis
        report.append("📈 Category Analysis\n", style="bold magenta")
        category_stats = {}

        for execution in executions:
            category = execution.test_case.category.value
            if category not in category_stats:
                category_stats[category] = {"total": 0, "passed": 0, "failed": 0}

            category_stats[category]["total"] += 1
            if execution.result == TestResult.PASS:
                category_stats[category]["passed"] += 1
            elif execution.result == TestResult.FAIL:
                category_stats[category]["failed"] += 1

        for category, stats in sorted(category_stats.items()):
            total = stats["total"]
            passed = stats["passed"]
            compliance = (passed / max(total, 1)) * 100
            color = (
                "green" if compliance >= 90 else "yellow" if compliance >= 70 else "red"
            )

            report.append(
                f"  {category.replace('_', ' ').title()}: {compliance:.1f}% "
                f"({passed}/{total})\n",
                style=color,
            )

        # Critical findings
        report.append("\n🚨 Critical Findings\n", style="bold red")
        critical_findings = [
            e
            for e in executions
            if e.result == TestResult.FAIL and e.risk_level in ["HIGH", "CRITICAL"]
        ]

        if critical_findings:
            for finding in critical_findings[:10]:  # Limit to top 10
                report.append(
                    f"  ❌ {finding.test_case.test_id}: {finding.test_case.title}\n",
                    style="red",
                )
                if finding.recommendations:
                    report.append(
                        f"     💡 {finding.recommendations[0]}\n", style="yellow"
                    )
        else:
            report.append(
                "  ✅ No critical security issues identified\n", style="green"
            )

        # Recommendations
        report.append("\n💡 Priority Recommendations\n", style="bold yellow")
        all_recommendations = []
        for execution in executions:
            if execution.result == TestResult.FAIL and execution.recommendations:
                all_recommendations.extend(execution.recommendations)

        # Get unique recommendations (simplified)
        unique_recommendations = list(set(all_recommendations))[:10]

        for i, rec in enumerate(unique_recommendations, 1):
            report.append(f"  {i}. {rec}\n", style="yellow")

        return report

    def export_results(
        self, executions: List[TestExecution], output_path: Path
    ) -> None:
        """Export test results to JSON format."""
        export_data = {
            "metadata": {
                "export_time": datetime.datetime.now().isoformat(),
                "total_tests": len(executions),
                "framework_version": "1.0.0",
            },
            "summary": {
                "passed": len([e for e in executions if e.result == TestResult.PASS]),
                "failed": len([e for e in executions if e.result == TestResult.FAIL]),
                "warnings": len(
                    [e for e in executions if e.result == TestResult.WARNING]
                ),
                "skipped": len([e for e in executions if e.result == TestResult.SKIP]),
                "errors": len([e for e in executions if e.result == TestResult.ERROR]),
            },
            "executions": [],
        }

        for execution in executions:
            export_data["executions"].append(
                {
                    "test_id": execution.test_case.test_id,
                    "title": execution.test_case.title,
                    "category": execution.test_case.category.value,
                    "masvs_controls": execution.test_case.masvs_controls,
                    "result": execution.result.value,
                    "execution_time": execution.execution_time.isoformat(),
                    "evidence": execution.evidence,
                    "findings": execution.findings,
                    "error_message": execution.error_message,
                    "recommendations": execution.recommendations,
                    "risk_level": execution.risk_level,
                }
            )

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

        logging.info(f"MASTG test results exported to: {output_path}")

    def _initialize_default_tests(self) -> None:
        """Initialize default MASTG test cases."""
        # Platform Interaction Tests
        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-PLATFORM-01",
                title="App Permissions Analysis",
                description="Test that the app only requests necessary permissions and handles permission denials gracefully",
                category=MASTGCategory.PLATFORM_INTERACTION,
                masvs_controls=["MSTG-PLATFORM-01"],
                masvs_level=MASVSLevel.L1,
                cwe_ids=["CWE-250", "CWE-280"],
                owasp_mobile_refs=["M1", "M2"],
                automated=True,
                tools_required=["static_analysis", "manifest_parser"],
                expected_evidence=[
                    "permission_list",
                    "dangerous_permissions",
                    "custom_permissions",
                ],
            )
        )

        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-PLATFORM-02",
                title="WebView Implementation Security",
                description="Test WebView configurations for security vulnerabilities",
                category=MASTGCategory.PLATFORM_INTERACTION,
                masvs_controls=["MSTG-PLATFORM-02"],
                masvs_level=MASVSLevel.L1,
                cwe_ids=["CWE-79", "CWE-94"],
                owasp_mobile_refs=["M7"],
                automated=True,
                tools_required=["static_analysis", "webview_analyzer"],
                expected_evidence=[
                    "webview_settings",
                    "javascript_enabled",
                    "file_access_settings",
                ],
            )
        )

        # Data Storage Tests
        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-STORAGE-01",
                title="Sensitive Data in System Logs",
                description="Test that sensitive data is not written to system logs",
                category=MASTGCategory.DATA_STORAGE,
                masvs_controls=["MSTG-STORAGE-01"],
                masvs_level=MASVSLevel.L1,
                cwe_ids=["CWE-532", "CWE-200"],
                owasp_mobile_refs=["M2"],
                automated=True,
                tools_required=["dynamic_analysis", "log_monitor"],
                expected_evidence=["log_analysis", "sensitive_data_patterns"],
            )
        )

        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-STORAGE-02",
                title="Sensitive Data in App Data Directory",
                description="Test that sensitive data is not stored insecurely in the app data directory",
                category=MASTGCategory.DATA_STORAGE,
                masvs_controls=["MSTG-STORAGE-02"],
                masvs_level=MASVSLevel.L1,
                cwe_ids=["CWE-312", "CWE-313"],
                owasp_mobile_refs=["M2"],
                automated=True,
                tools_required=["static_analysis", "file_system_analysis"],
                expected_evidence=[
                    "app_data_analysis",
                    "sensitive_files",
                    "file_permissions",
                ],
            )
        )

        # Network Communication Tests
        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-NETWORK-01",
                title="Network Communication Encryption",
                description="Test that network communication uses appropriate encryption",
                category=MASTGCategory.NETWORK_COMMUNICATION,
                masvs_controls=["MSTG-NETWORK-01"],
                masvs_level=MASVSLevel.L1,
                cwe_ids=["CWE-319", "CWE-326"],
                owasp_mobile_refs=["M4"],
                automated=True,
                tools_required=["network_analysis", "certificate_analysis"],
                expected_evidence=[
                    "tls_configuration",
                    "certificate_validation",
                    "network_traffic",
                ],
            )
        )

        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-NETWORK-02",
                title="Certificate Pinning Implementation",
                description="Test certificate pinning implementation for critical connections",
                category=MASTGCategory.NETWORK_COMMUNICATION,
                masvs_controls=["MSTG-NETWORK-02"],
                masvs_level=MASVSLevel.L2,
                cwe_ids=["CWE-295"],
                owasp_mobile_refs=["M4"],
                automated=True,
                tools_required=["network_analysis", "certificate_analysis"],
                expected_evidence=["pinning_implementation", "pinning_bypass_attempts"],
            )
        )

        # Cryptography Tests
        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-CRYPTO-01",
                title="Cryptographic Key Management",
                description="Test cryptographic key generation, storage, and management practices",
                category=MASTGCategory.CRYPTOGRAPHY,
                masvs_controls=["MSTG-CRYPTO-01"],
                masvs_level=MASVSLevel.L1,
                cwe_ids=["CWE-320", "CWE-321"],
                owasp_mobile_refs=["M5"],
                automated=True,
                tools_required=["static_analysis", "crypto_analyzer"],
                expected_evidence=[
                    "key_generation",
                    "key_storage",
                    "crypto_algorithms",
                ],
            )
        )

        # Authentication Tests
        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-AUTH-01",
                title="Authentication Architecture",
                description="Test the authentication architecture and implementation",
                category=MASTGCategory.AUTHENTICATION,
                masvs_controls=["MSTG-AUTH-01"],
                masvs_level=MASVSLevel.L1,
                cwe_ids=["CWE-287", "CWE-306"],
                owasp_mobile_refs=["M6"],
                automated=True,
                tools_required=["static_analysis", "dynamic_analysis"],
                expected_evidence=[
                    "auth_mechanisms",
                    "session_management",
                    "token_handling",
                ],
            )
        )

        # Code Quality Tests
        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-CODE-01",
                title="Code Injection Vulnerabilities",
                description="Test for code injection vulnerabilities in the application",
                category=MASTGCategory.CODE_QUALITY,
                masvs_controls=["MSTG-CODE-01"],
                masvs_level=MASVSLevel.L1,
                cwe_ids=["CWE-94", "CWE-95"],
                owasp_mobile_refs=["M7"],
                automated=True,
                tools_required=["static_analysis", "dynamic_analysis"],
                expected_evidence=[
                    "injection_points",
                    "input_validation",
                    "output_encoding",
                ],
            )
        )

        # Tampering and Reverse Engineering Tests
        self.register_test_case(
            MASTGTestCase(
                test_id="MSTG-RESILIENCE-01",
                title="Obfuscation Analysis",
                description="Test application obfuscation and anti-reverse engineering measures",
                category=MASTGCategory.TAMPERING_REVERSE_ENGINEERING,
                masvs_controls=["MSTG-RESILIENCE-01"],
                masvs_level=MASVSLevel.R,
                cwe_ids=["CWE-656"],
                owasp_mobile_refs=["M8", "M9"],
                automated=True,
                tools_required=["static_analysis", "reverse_engineering_tools"],
                expected_evidence=[
                    "obfuscation_level",
                    "anti_debug_measures",
                    "integrity_checks",
                ],
            )
        )

# Global framework instance
mastg_framework = MASTGFramework()

def get_mastg_framework() -> MASTGFramework:
    """Get the global MASTG framework instance."""
    return mastg_framework
