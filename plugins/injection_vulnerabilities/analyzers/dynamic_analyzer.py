"""
Dynamic Injection Vulnerability Analyzer

This module handles dynamic analysis of injection vulnerabilities using various
dynamic analysis tools and techniques.
"""

import logging
import time
from typing import Dict, Any, List, Optional

from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)

class DynamicInjectionAnalyzer:
    """
    Dynamic analyzer for injection vulnerabilities.
    
    Provides dynamic analysis capabilities for detecting injection vulnerabilities
    through runtime testing and analysis.
    """
    
    def __init__(self):
        """Initialize the dynamic analyzer."""
        self.timeout_seconds = 30
        self.max_retry_attempts = 3
        
    def analyze_injection_vulnerabilities(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Analyze injection vulnerabilities using dynamic analysis.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Dynamic analysis results
        """
        logger.info("Starting dynamic injection vulnerability analysis")
        
        results = {
            "enabled": True,
            "drozer_analysis": {},
            "runtime_analysis": {},
            "vulnerabilities": [],
            "analysis_time": 0.0,
            "status": "pending"
        }
        
        try:
            start_time = time.time()
            
            # Check if Drozer is available
            if hasattr(apk_ctx, 'drozer') and apk_ctx.drozer:
                logger.info("Drozer available - performing drozer analysis")
                drozer_results = self._perform_drozer_analysis(apk_ctx)
                results["drozer_analysis"] = drozer_results
                
                # Extract vulnerabilities from Drozer results
                if drozer_results.get("has_vulnerabilities", False):
                    vulnerabilities = self.extract_vulnerabilities_from_drozer_results(drozer_results)
                    results["vulnerabilities"].extend(vulnerabilities)
            else:
                logger.info("Drozer not available - skipping drozer analysis")
                results["drozer_analysis"] = {"enabled": False, "reason": "drozer_not_available"}
            
            # Perform additional runtime analysis if available
            runtime_results = self._perform_runtime_analysis(apk_ctx)
            results["runtime_analysis"] = runtime_results
            
            results["analysis_time"] = time.time() - start_time
            results["status"] = "completed"
            
            logger.info(f"Dynamic analysis completed in {results['analysis_time']:.2f}s")
            
        except Exception as e:
            logger.error(f"Dynamic analysis failed: {str(e)}")
            results["status"] = "failed"
            results["error"] = str(e)
        
        return results
    
    def _perform_drozer_analysis(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform Drozer-based injection vulnerability analysis.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Drozer analysis results
        """
        results = {
            "enabled": True,
            "connection_status": {},
            "injection_scan": {},
            "provider_scan": {},
            "has_vulnerabilities": False,
            "raw_output": "",
            "analysis_time": 0.0
        }
        
        try:
            start_time = time.time()
            
            # Check Drozer connection
            connection_status = self._check_drozer_connection(apk_ctx.drozer)
            results["connection_status"] = connection_status
            
            if not connection_status.get("connected", False):
                results["enabled"] = False
                results["error"] = connection_status.get("error", "Connection failed")
                return results
            
            # Perform injection scan
            injection_results = self._perform_injection_scan(apk_ctx)
            results["injection_scan"] = injection_results
            
            # Perform provider scan
            provider_results = self._perform_provider_scan(apk_ctx)
            results["provider_scan"] = provider_results
            
            # Analyze results for vulnerabilities
            results["has_vulnerabilities"] = self._analyze_drozer_results(injection_results, provider_results)
            
            # Store raw output
            results["raw_output"] = injection_results.get("raw_output", "")
            
            results["analysis_time"] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Drozer analysis failed: {str(e)}")
            results["enabled"] = False
            results["error"] = str(e)
        
        return results
    
    def _check_drozer_connection(self, drozer) -> Dict[str, Any]:
        """
        Check Drozer connection status.
        
        Args:
            drozer: Drozer instance
            
        Returns:
            Dict[str, Any]: Connection status
        """
        try:
            if hasattr(drozer, 'get_connection_status'):
                status = drozer.get_connection_status()
                return {
                    "connected": status.get("connected", False),
                    "error": status.get("last_error", ""),
                    "method": "get_connection_status"
                }
            else:
                # Fallback: try a simple command
                test_result = self._execute_drozer_command(drozer, "list")
                return {
                    "connected": test_result.get("success", False),
                    "error": test_result.get("error", ""),
                    "method": "test_command"
                }
        except Exception as e:
            return {
                "connected": False,
                "error": str(e),
                "method": "exception"
            }
    
    def _perform_injection_scan(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform injection vulnerability scan using Drozer.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Injection scan results
        """
        results = {
            "enabled": True,
            "command": "",
            "success": False,
            "raw_output": "",
            "analysis_time": 0.0
        }
        
        try:
            start_time = time.time()
            
            # Build injection scan command
            command = f"run scanner.provider.injection -a {apk_ctx.package_name}"
            results["command"] = command
            
            # Execute command
            exec_result = self._execute_drozer_command(apk_ctx.drozer, command)
            results.update(exec_result)
            
            results["analysis_time"] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Injection scan failed: {str(e)}")
            results["enabled"] = False
            results["error"] = str(e)
        
        return results
    
    def _perform_provider_scan(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform provider information scan using Drozer.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Provider scan results
        """
        results = {
            "enabled": True,
            "commands": [],
            "results": [],
            "analysis_time": 0.0
        }
        
        try:
            start_time = time.time()
            
            # Provider scan commands
            commands = [
                f"run app.provider.info -a {apk_ctx.package_name}",
                f"run scanner.provider.sqltables -a {apk_ctx.package_name}"
            ]
            
            results["commands"] = commands
            
            # Execute each command
            for command in commands:
                exec_result = self._execute_drozer_command(apk_ctx.drozer, command)
                results["results"].append({
                    "command": command,
                    "result": exec_result
                })
            
            results["analysis_time"] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Provider scan failed: {str(e)}")
            results["enabled"] = False
            results["error"] = str(e)
        
        return results
    
    def _execute_drozer_command(self, drozer, command: str) -> Dict[str, Any]:
        """
        Execute a Drozer command with appropriate error handling.
        
        Args:
            drozer: Drozer instance
            command: Command to execute
            
        Returns:
            Dict[str, Any]: Execution results
        """
        try:
            # Try different execution methods
            if hasattr(drozer, 'execute_command_safe'):
                output = drozer.execute_command_safe(command, "Command failed", timeout=self.timeout_seconds)
                return {
                    "success": True,
                    "raw_output": output,
                    "method": "execute_command_safe"
                }
            elif hasattr(drozer, 'run_command_safe'):
                output = drozer.run_command_safe(command, "Command failed")
                return {
                    "success": True,
                    "raw_output": output,
                    "method": "run_command_safe"
                }
            elif hasattr(drozer, 'execute_command'):
                success, output = drozer.execute_command(command)
                return {
                    "success": success,
                    "raw_output": output,
                    "method": "execute_command"
                }
            else:
                return {
                    "success": False,
                    "error": "No suitable execution method found",
                    "method": "none"
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "method": "exception"
            }
    
    def _analyze_drozer_results(self, injection_results: Dict[str, Any], provider_results: Dict[str, Any]) -> bool:
        """
        Analyze Drozer results to determine if vulnerabilities exist.
        
        Args:
            injection_results: Injection scan results
            provider_results: Provider scan results
            
        Returns:
            bool: True if vulnerabilities are detected
        """
        # Check injection scan results
        if injection_results.get("success", False):
            output = injection_results.get("raw_output", "")
            if self._analyze_injection_output(output):
                return True
        
        # Check provider scan results
        for result in provider_results.get("results", []):
            if result.get("result", {}).get("success", False):
                output = result.get("result", {}).get("raw_output", "")
                if self._analyze_provider_output(output):
                    return True
        
        return False
    
    def _analyze_injection_output(self, output: str) -> bool:
        """
        Analyze injection scan output for vulnerabilities.
        
        Args:
            output: Raw output from injection scan
            
        Returns:
            bool: True if vulnerabilities detected
        """
        if not output:
            return False
        
        output_lower = output.lower()
        
        # Strong non-vulnerability indicators
        non_vuln_indicators = [
            "not vulnerable:",
            "no vulnerabilities found",
            "injection in projection:\n  no vulnerabilities found",
            "injection in selection:\n  no vulnerabilities found",
        ]
        
        # Check for strong negative indicators
        for indicator in non_vuln_indicators:
            if indicator in output_lower:
                return False
        
        # Look for vulnerability evidence
        vuln_indicators = [
            "sql syntax error",
            "database error",
            "sqlite error",
            "injection successful",
            "data extracted",
            "vulnerable:",
            "error:",
            "exception:"
        ]
        
        # Check for vulnerability evidence
        for indicator in vuln_indicators:
            if indicator in output_lower:
                return True
        
        return False
    
    def _analyze_provider_output(self, output: str) -> bool:
        """
        Analyze provider scan output for vulnerabilities.
        
        Args:
            output: Raw output from provider scan
            
        Returns:
            bool: True if vulnerabilities detected
        """
        if not output:
            return False
        
        output_lower = output.lower()
        
        # Look for suspicious provider configurations
        vuln_indicators = [
            "exported provider",
            "world readable",
            "world writable",
            "no permissions required",
            "accessible to all"
        ]
        
        for indicator in vuln_indicators:
            if indicator in output_lower:
                return True
        
        return False
    
    def _perform_runtime_analysis(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform additional runtime analysis.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Runtime analysis results
        """
        results = {
            "enabled": False,
            "reason": "not_implemented",
            "analysis_time": 0.0
        }
        
        # Placeholder for future runtime analysis capabilities
        # This could include instrumentation, hooking, etc.
        
        return results
    
    def extract_vulnerabilities_from_drozer_results(self, drozer_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract structured vulnerabilities from Drozer results.
        
        Args:
            drozer_results: Drozer analysis results
            
        Returns:
            List[Dict[str, Any]]: List of structured vulnerabilities
        """
        vulnerabilities = []
        
        # Extract from injection scan
        injection_scan = drozer_results.get("injection_scan", {})
        if injection_scan.get("success", False):
            output = injection_scan.get("raw_output", "")
            if self._analyze_injection_output(output):
                vulnerabilities.append({
                    "type": "sql_injection",
                    "severity": "HIGH",
                    "confidence": 0.8,
                    "description": "SQL injection vulnerability detected in content provider",
                    "location": "content_provider",
                    "source": "drozer_injection_scan",
                    "evidence": output[:200] + "..." if len(output) > 200 else output,
                    "remediation": [
                        "Use parameterized queries",
                        "Validate all input data",
                        "Implement proper access controls"
                    ]
                })
        
        # Extract from provider scan
        provider_scan = drozer_results.get("provider_scan", {})
        for result in provider_scan.get("results", []):
            if result.get("result", {}).get("success", False):
                output = result.get("result", {}).get("raw_output", "")
                if self._analyze_provider_output(output):
                    vulnerabilities.append({
                        "type": "provider_exposure",
                        "severity": "MEDIUM",
                        "confidence": 0.7,
                        "description": "Content provider exposed without proper access controls",
                        "location": "content_provider",
                        "source": "drozer_provider_scan",
                        "evidence": output[:200] + "..." if len(output) > 200 else output,
                        "remediation": [
                            "Implement proper permission checks",
                            "Restrict provider access",
                            "Use signature-level permissions"
                        ]
                    })
        
        return vulnerabilities
    
    def test_sql_injection_with_drozer(self, drozer_manager, package_name: str) -> str:
        """
        Legacy compatibility function for SQL injection testing.
        
        Args:
            drozer_manager: Drozer manager instance
            package_name: Package name to test
            
        Returns:
            str: Test results
        """
        if not drozer_manager:
            return "⚠️ SQL injection testing requires drozer connectivity"
        
        try:
            # Check connection status
            status = drozer_manager.get_connection_status()
            if not status.get("connected", False):
                error_msg = status.get("last_error", "Unknown connection error")
                return f"⚠️ Drozer connection failed: {error_msg}"
            
            # Run injection commands
            injection_commands = [
                f"run scanner.provider.injection -a {package_name}",
                f"run scanner.provider.sqltables -a {package_name}",
                f"run app.provider.info -a {package_name}"
            ]
            
            results = []
            for cmd in injection_commands:
                # Check for shutdown
                if self._check_shutdown():
                    results.append("🛑 Analysis cancelled due to shutdown request")
                    break
                
                try:
                    exec_result = self._execute_drozer_command(drozer_manager, cmd)
                    if exec_result.get("success", False):
                        results.append(f"✅ {cmd}: {exec_result.get('raw_output', '')[:200]}...")
                    else:
                        results.append(f"⚠️ {cmd}: {exec_result.get('error', 'Failed')}")
                except Exception as e:
                    results.append(f"❌ {cmd}: Command failed - {str(e)}")
            
            return "\n".join(results) if results else "No SQL injection results available"
            
        except Exception as e:
            return f"❌ SQL injection testing failed: {str(e)}"
    
    def _check_shutdown(self) -> bool:
        """Check if graceful shutdown has been requested."""
        try:
            from core.graceful_shutdown_manager import is_shutdown_requested
            return is_shutdown_requested()
        except ImportError:
            return False 