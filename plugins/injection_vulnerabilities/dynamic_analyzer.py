"""
Injection Vulnerabilities - Dynamic Analyzer Component

This module provides dynamic analysis capabilities using Drozer for SQL injection
testing and vulnerability detection in content providers.
"""

import logging
import time
from typing import Dict, List, Optional, Any, Tuple

from core.apk_ctx import APKContext
from plugins.injection_vulnerabilities.data_structures import (
    DynamicAnalysisResult, InjectionVulnerability, VulnerabilityType,
    SeverityLevel, RiskLevel, AnalysisMethod, InjectionAnalysisConfiguration,
    create_sql_injection_vulnerability
)

# Import graceful shutdown support
try:
    from core.graceful_shutdown_manager import is_shutdown_requested
    GRACEFUL_SHUTDOWN_AVAILABLE = True
except ImportError:
    GRACEFUL_SHUTDOWN_AVAILABLE = False
    def is_shutdown_requested():
        return False

class DynamicInjectionAnalyzer:
    """Dynamic analyzer for injection vulnerabilities using Drozer."""
    
    def __init__(self, config: Optional[InjectionAnalysisConfiguration] = None):
        """Initialize the dynamic analyzer."""
        self.config = config or InjectionAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
    
    def analyze_injection_vulnerabilities(self, apk_ctx: APKContext) -> Optional[DynamicAnalysisResult]:
        """Perform dynamic analysis using Drozer for SQL injection vulnerabilities."""
        if not self.config.enable_dynamic_analysis:
            self.logger.info("Dynamic analysis disabled in configuration")
            return None
        
        # Check for Drozer availability
        if not self._is_drozer_available(apk_ctx):
            self.logger.warning("Drozer not available for dynamic analysis")
            return None
        
        # Check for shutdown at the beginning
        if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
            self.logger.info("Dynamic analysis cancelled due to shutdown request")
            return None
        
        try:
            # Test Drozer connectivity
            if not self._test_drozer_connectivity(apk_ctx):
                self.logger.warning("Drozer connectivity test failed")
                return None
            
            # Perform SQL injection scan
            return self._perform_sql_injection_scan(apk_ctx)
            
        except Exception as e:
            self.logger.error(f"Dynamic analysis failed: {e}")
            return None
    
    def _is_drozer_available(self, apk_ctx: APKContext) -> bool:
        """Check if Drozer is available for analysis."""
        if not hasattr(apk_ctx, 'drozer') or not apk_ctx.drozer:
            return False
        
        if not hasattr(apk_ctx, 'package_name') or not apk_ctx.package_name:
            return False
        
        return True
    
    def _test_drozer_connectivity(self, apk_ctx: APKContext) -> bool:
        """Test Drozer connectivity with a simple command."""
        try:
            # Check connection status if available
            if hasattr(apk_ctx.drozer, 'get_connection_status'):
                status = apk_ctx.drozer.get_connection_status()
                if not status.get('connected', False):
                    return False
            
            # Test with a simple list command (most reliable)
            start_time = time.time()
            test_result = None
            
            if hasattr(apk_ctx.drozer, 'execute_command_safe'):
                test_result = apk_ctx.drozer.execute_command_safe(
                    "list",  # Simple command instead of package info
                    "Drozer not available",
                    timeout=8  # Reduced timeout from 10 to 8 seconds
                )
            elif hasattr(apk_ctx.drozer, 'run_command_safe'):
                test_result = apk_ctx.drozer.run_command_safe(
                    "list",  # Simple command
                    "Drozer not available"
                )
            
            test_time = time.time() - start_time
            self.logger.info(f"Drozer connectivity test completed in {test_time:.1f}s")
            
            # Check if test succeeded
            if not test_result or "not available" in test_result.lower():
                return False
            
            # Verify the output indicates successful connection
            if "app.activity" in test_result.lower() or "modules" in test_result.lower():
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Drozer connectivity test failed: {e}")
            return False
    
    def _perform_sql_injection_scan(self, apk_ctx: APKContext) -> DynamicAnalysisResult:
        """Perform SQL injection scan using Drozer."""
        start_time = time.time()
        
        # Define injection commands to execute
        injection_commands = [
            f"run scanner.provider.injection -a {apk_ctx.package_name}",
            f"run scanner.provider.sqltables -a {apk_ctx.package_name}",
            f"run app.provider.info -a {apk_ctx.package_name}"
        ]
        
        all_vulnerabilities = []
        all_outputs = []
        
        for command in injection_commands:
            # Check for shutdown before each command
            if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                self.logger.info("Dynamic analysis cancelled during scan")
                break
            
            try:
                result = self._execute_injection_command(apk_ctx, command)
                if result:
                    all_outputs.append(f"Command: {command}\n{result}")
                    
                    # Analyze result for vulnerabilities
                    vulnerabilities = self._analyze_injection_result(result, command)
                    all_vulnerabilities.extend(vulnerabilities)
                    
            except Exception as e:
                self.logger.error(f"Failed to execute command {command}: {e}")
                all_outputs.append(f"Command: {command}\nError: {str(e)}")
        
        execution_time = time.time() - start_time
        
        # Create dynamic analysis result
        primary_command = injection_commands[0]
        combined_output = "\n\n".join(all_outputs)
        
        return DynamicAnalysisResult(
            command_executed=primary_command,
            execution_time=execution_time,
            success=len(all_vulnerabilities) == 0,  # Success if no vulnerabilities found
            raw_output=combined_output,
            vulnerabilities_found=all_vulnerabilities
        )
    
    def _execute_injection_command(self, apk_ctx: APKContext, command: str) -> Optional[str]:
        """Execute a single injection command using Drozer."""
        try:
            start_time = time.time()
            result = None
            
            if hasattr(apk_ctx.drozer, 'execute_command_safe'):
                result = apk_ctx.drozer.execute_command_safe(
                    command,
                    "Command execution failed",
                    timeout=self.config.drozer_timeout_seconds
                )
            elif hasattr(apk_ctx.drozer, 'run_command_safe'):
                result = apk_ctx.drozer.run_command_safe(
                    command,
                    "Command execution failed"
                )
            
            execution_time = time.time() - start_time
            self.logger.info(f"Command '{command}' executed in {execution_time:.1f}s")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return None
    
    def _analyze_injection_result(self, result: str, command: str) -> List[InjectionVulnerability]:
        """Analyze Drozer injection result for vulnerabilities."""
        vulnerabilities = []
        
        if not result:
            return vulnerabilities
        
        result_lower = result.lower()
        
        # Strong indicators that no vulnerabilities exist
        no_vulnerability_indicators = [
            "not vulnerable:",
            "no vulnerabilities found",
            "injection in projection:\n  no vulnerabilities found",
            "injection in selection:\n  no vulnerabilities found",
        ]
        
        # Check for strong non-vulnerability indicators
        for indicator in no_vulnerability_indicators:
            if indicator in result_lower:
                return vulnerabilities
        
        # Look for vulnerability evidence
        if self._has_vulnerability_evidence(result):
            vulnerability = self._create_vulnerability_from_result(result, command)
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _has_vulnerability_evidence(self, result: str) -> bool:
        """Check if result contains evidence of vulnerabilities."""
        result_lower = result.lower()
        
        # Look for vulnerability section headers followed by content
        lines = result.split("\n")
        in_vulnerable_section = False
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Check if entering a "Vulnerable:" section
            if line_lower.startswith("vulnerable:"):
                in_vulnerable_section = True
                continue
            
            # If in vulnerable section and find evidence
            if in_vulnerable_section and line_lower:
                if not line_lower.startswith("content://"):
                    # Look for actual vulnerability descriptions
                    vulnerability_evidence = [
                        "sql syntax error",
                        "database error",
                        "sqlite error",
                        "injection successful",
                        "data extracted",
                        "error:",
                        "exception:",
                        "successful",
                    ]
                    
                    if any(evidence in line_lower for evidence in vulnerability_evidence):
                        return True
        
        # Check for vulnerability evidence in specific injection sections
        injection_sections = ["injection in projection:", "injection in selection:"]
        
        for section in injection_sections:
            if section in result_lower:
                section_start = result_lower.find(section)
                if section_start != -1:
                    # Get content after section header
                    section_content = result_lower[section_start + len(section):].split("\n")[0:3]
                    section_text = " ".join(section_content).strip()
                    
                    # Check for positive evidence
                    if section_text and not any(
                        negative in section_text 
                        for negative in ["no vulnerabilities found", "not vulnerable"]
                    ):
                        evidence_patterns = [
                            "sql syntax error",
                            "database error",
                            "injection successful",
                            "error",
                            "exception",
                        ]
                        
                        if any(evidence in section_text for evidence in evidence_patterns):
                            return True
        
        return False
    
    def _create_vulnerability_from_result(self, result: str, command: str) -> InjectionVulnerability:
        """Create vulnerability from Drozer result."""
        # Extract relevant information from result
        evidence = self._extract_evidence(result)
        confidence = self._calculate_confidence(result, evidence)
        
        # Determine severity based on evidence
        severity = self._determine_severity(evidence)
        
        return create_sql_injection_vulnerability(
            description="SQL injection vulnerability detected through dynamic analysis",
            severity=severity,
            confidence=confidence,
            location="Content Provider",
            method=AnalysisMethod.DYNAMIC_DROZER,
            evidence=evidence,
            code_snippet=self._extract_code_snippet(result)
        )
    
    def _extract_evidence(self, result: str) -> str:
        """Extract evidence from Drozer result."""
        # Look for vulnerable sections
        lines = result.split("\n")
        evidence_lines = []
        
        for i, line in enumerate(lines):
            if "vulnerable:" in line.lower() or "injection" in line.lower():
                # Include this line and next few lines as evidence
                evidence_lines.extend(lines[i:i+3])
                break
        
        if evidence_lines:
            return "\n".join(evidence_lines[:5])  # Limit to 5 lines
        
        # Fallback to first few lines
        return "\n".join(lines[:3])
    
    def _calculate_confidence(self, result: str, evidence: str) -> float:
        """Calculate confidence score for vulnerability."""
        base_confidence = 0.7
        
        # Increase confidence for strong indicators
        strong_indicators = [
            "sql syntax error",
            "database error",
            "injection successful",
            "sqlite error"
        ]
        
        evidence_lower = evidence.lower()
        for indicator in strong_indicators:
            if indicator in evidence_lower:
                base_confidence += 0.1
        
        # Increase confidence for detailed error messages
        if len(evidence) > 100:
            base_confidence += 0.05
        
        # Increase confidence for multiple vulnerability types
        if "injection in projection" in result.lower() and "injection in selection" in result.lower():
            base_confidence += 0.1
        
        return min(1.0, base_confidence)
    
    def _determine_severity(self, evidence: str) -> SeverityLevel:
        """Determine severity level based on evidence."""
        evidence_lower = evidence.lower()
        
        # Critical indicators
        if any(indicator in evidence_lower for indicator in [
            "data extracted",
            "injection successful",
            "database error"
        ]):
            return SeverityLevel.CRITICAL
        
        # High indicators
        if any(indicator in evidence_lower for indicator in [
            "sql syntax error",
            "sqlite error",
            "exception"
        ]):
            return SeverityLevel.HIGH
        
        # Default to medium for detected vulnerabilities
        return SeverityLevel.MEDIUM
    
    def _extract_code_snippet(self, result: str) -> Optional[str]:
        """Extract code snippet from result if available."""
        # Look for code-like patterns in result
        lines = result.split("\n")
        
        for line in lines:
            if any(keyword in line.lower() for keyword in ["select", "insert", "update", "delete"]):
                return line.strip()
        
        return None
    
    def get_analysis_summary(self, result: DynamicAnalysisResult) -> Dict[str, Any]:
        """Generate summary of dynamic analysis results."""
        summary = {
            'analysis_method': 'dynamic_drozer',
            'execution_time': result.execution_time,
            'success': result.success,
            'vulnerabilities_found': len(result.vulnerabilities_found),
            'command_executed': result.command_executed
        }
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in result.vulnerabilities_found:
            severity = vuln.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary['severity_breakdown'] = severity_counts
        
        return summary 