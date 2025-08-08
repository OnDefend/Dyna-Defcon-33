"""
Drozer Analyzer for Injection Vulnerabilities

This module provides specialized Drozer analysis capabilities for detecting
injection vulnerabilities in Android applications.
"""

import logging
import time
from typing import Dict, Any, List, Optional

from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)

class DrozerInjectionAnalyzer:
    """
    Specialized Drozer analyzer for injection vulnerabilities.
    
    Provides focused Drozer analysis capabilities for injection vulnerability detection.
    """
    
    def __init__(self):
        """Initialize the Drozer analyzer."""
        self.timeout_seconds = 30
        self.max_retry_attempts = 3
        self.connection_test_timeout = 10
        
    def analyze_injection_vulnerabilities(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Analyze injection vulnerabilities using Drozer.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Drozer analysis results
        """
        logger.info("Starting Drozer injection vulnerability analysis")
        
        results = {
            "enabled": True,
            "connection_test": {},
            "injection_scan": {},
            "provider_info": {},
            "sql_tables_scan": {},
            "has_vulnerabilities": False,
            "vulnerability_details": [],
            "analysis_time": 0.0,
            "status": "pending"
        }
        
        try:
            start_time = time.time()
            
            # Test Drozer connection
            logger.info("Testing Drozer connection")
            connection_test = self._test_drozer_connection(apk_ctx)
            results["connection_test"] = connection_test
            
            if not connection_test.get("success", False):
                results["enabled"] = False
                results["status"] = "failed"
                results["error"] = connection_test.get("error", "Connection failed")
                return results
            
            # Perform injection scan
            logger.info("Performing injection vulnerability scan")
            injection_scan = self._perform_injection_scan(apk_ctx)
            results["injection_scan"] = injection_scan
            
            # Get provider information
            logger.info("Gathering provider information")
            provider_info = self._get_provider_info(apk_ctx)
            results["provider_info"] = provider_info
            
            # Perform SQL tables scan
            logger.info("Performing SQL tables scan")
            sql_tables_scan = self._perform_sql_tables_scan(apk_ctx)
            results["sql_tables_scan"] = sql_tables_scan
            
            # Analyze all results for vulnerabilities
            results["has_vulnerabilities"] = self._analyze_all_results(results)
            
            # Extract detailed vulnerability information
            if results["has_vulnerabilities"]:
                results["vulnerability_details"] = self._extract_vulnerability_details(results)
            
            results["analysis_time"] = time.time() - start_time
            results["status"] = "completed"
            
            logger.info(f"Drozer analysis completed in {results['analysis_time']:.2f}s")
            
        except Exception as e:
            logger.error(f"Drozer analysis failed: {str(e)}")
            results["status"] = "failed"
            results["error"] = str(e)
        
        return results
    
    def _test_drozer_connection(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Test Drozer connection with comprehensive checks.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Connection test results
        """
        results = {
            "success": False,
            "method": "unknown",
            "response_time": 0.0,
            "error": "",
            "test_command": "",
            "test_output": ""
        }
        
        try:
            start_time = time.time()
            
            # First try connection status if available
            if hasattr(apk_ctx.drozer, 'get_connection_status'):
                status = apk_ctx.drozer.get_connection_status()
                if status.get("connected", False):
                    results.update({
                        "success": True,
                        "method": "get_connection_status",
                        "response_time": time.time() - start_time,
                        "test_command": "get_connection_status",
                        "test_output": str(status)
                    })
                    return results
                else:
                    results["error"] = status.get("last_error", "Not connected")
            
            # Try simple test command
            test_command = f"run app.package.info -a {apk_ctx.package_name}"
            results["test_command"] = test_command
            
            exec_result = self._execute_drozer_command(apk_ctx.drozer, test_command, self.connection_test_timeout)
            
            if exec_result.get("success", False):
                output = exec_result.get("raw_output", "")
                if output and "not available" not in output.lower():
                    results.update({
                        "success": True,
                        "method": "test_command",
                        "response_time": time.time() - start_time,
                        "test_output": output[:200] + "..." if len(output) > 200 else output
                    })
                else:
                    results["error"] = "Command executed but returned no valid output"
            else:
                results["error"] = exec_result.get("error", "Command execution failed")
            
        except Exception as e:
            results["error"] = f"Connection test exception: {str(e)}"
        
        return results
    
    def _perform_injection_scan(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform injection vulnerability scan.
        
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
            "parsed_results": {},
            "execution_time": 0.0
        }
        
        try:
            start_time = time.time()
            
            # Build and execute injection scan command
            command = f"run scanner.provider.injection -a {apk_ctx.package_name}"
            results["command"] = command
            
            exec_result = self._execute_drozer_command(apk_ctx.drozer, command, self.timeout_seconds)
            results.update(exec_result)
            
            # Parse injection scan results
            if exec_result.get("success", False):
                raw_output = exec_result.get("raw_output", "")
                parsed = self._parse_injection_scan_output(raw_output)
                results["parsed_results"] = parsed
            
            results["execution_time"] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Injection scan failed: {str(e)}")
            results["enabled"] = False
            results["error"] = str(e)
        
        return results
    
    def _get_provider_info(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Get content provider information.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Provider information results
        """
        results = {
            "enabled": True,
            "command": "",
            "success": False,
            "raw_output": "",
            "parsed_results": {},
            "execution_time": 0.0
        }
        
        try:
            start_time = time.time()
            
            # Build and execute provider info command
            command = f"run app.provider.info -a {apk_ctx.package_name}"
            results["command"] = command
            
            exec_result = self._execute_drozer_command(apk_ctx.drozer, command, self.timeout_seconds)
            results.update(exec_result)
            
            # Parse provider info results
            if exec_result.get("success", False):
                raw_output = exec_result.get("raw_output", "")
                parsed = self._parse_provider_info_output(raw_output)
                results["parsed_results"] = parsed
            
            results["execution_time"] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Provider info scan failed: {str(e)}")
            results["enabled"] = False
            results["error"] = str(e)
        
        return results
    
    def _perform_sql_tables_scan(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform SQL tables scan.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: SQL tables scan results
        """
        results = {
            "enabled": True,
            "command": "",
            "success": False,
            "raw_output": "",
            "parsed_results": {},
            "execution_time": 0.0
        }
        
        try:
            start_time = time.time()
            
            # Build and execute SQL tables scan command
            command = f"run scanner.provider.sqltables -a {apk_ctx.package_name}"
            results["command"] = command
            
            exec_result = self._execute_drozer_command(apk_ctx.drozer, command, self.timeout_seconds)
            results.update(exec_result)
            
            # Parse SQL tables scan results
            if exec_result.get("success", False):
                raw_output = exec_result.get("raw_output", "")
                parsed = self._parse_sql_tables_output(raw_output)
                results["parsed_results"] = parsed
            
            results["execution_time"] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"SQL tables scan failed: {str(e)}")
            results["enabled"] = False
            results["error"] = str(e)
        
        return results
    
    def _execute_drozer_command(self, drozer, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a Drozer command with timeout and error handling.
        
        Args:
            drozer: Drozer instance
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            Dict[str, Any]: Execution results
        """
        try:
            # Try different execution methods
            if hasattr(drozer, 'execute_command_safe'):
                output = drozer.execute_command_safe(command, "Command failed", timeout=timeout)
                return {
                    "success": output and "Command failed" not in output,
                    "raw_output": output if output else "",
                    "method": "execute_command_safe",
                    "timeout": timeout
                }
            elif hasattr(drozer, 'run_command_safe'):
                output = drozer.run_command_safe(command, "Command failed")
                return {
                    "success": output and "Command failed" not in output,
                    "raw_output": output if output else "",
                    "method": "run_command_safe",
                    "timeout": timeout
                }
            elif hasattr(drozer, 'execute_command'):
                success, output = drozer.execute_command(command)
                return {
                    "success": success,
                    "raw_output": output if output else "",
                    "method": "execute_command",
                    "timeout": timeout
                }
            else:
                return {
                    "success": False,
                    "error": "No suitable execution method found",
                    "method": "none",
                    "timeout": timeout
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "method": "exception",
                "timeout": timeout
            }
    
    def _parse_injection_scan_output(self, output: str) -> Dict[str, Any]:
        """
        Parse injection scan output for vulnerability information.
        
        Args:
            output: Raw output from injection scan
            
        Returns:
            Dict[str, Any]: Parsed results
        """
        parsed = {
            "has_vulnerabilities": False,
            "vulnerable_providers": [],
            "injection_types": [],
            "vulnerability_details": []
        }
        
        if not output:
            return parsed
        
        output_lower = output.lower()
        lines = output.split('\n')
        
        # Check for vulnerability indicators
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
        
        # Check for non-vulnerability indicators
        non_vuln_indicators = [
            "not vulnerable:",
            "no vulnerabilities found",
            "injection in projection:\n  no vulnerabilities found",
            "injection in selection:\n  no vulnerabilities found",
        ]
        
        # First check for strong non-vulnerability indicators
        for indicator in non_vuln_indicators:
            if indicator in output_lower:
                return parsed
        
        # Look for vulnerability evidence
        for line in lines:
            line_lower = line.lower().strip()
            
            # Check for vulnerability indicators
            for indicator in vuln_indicators:
                if indicator in line_lower:
                    parsed["has_vulnerabilities"] = True
                    parsed["vulnerability_details"].append({
                        "type": "injection_vulnerability",
                        "evidence": line.strip(),
                        "indicator": indicator
                    })
            
            # Parse provider-specific vulnerabilities
            if line_lower.startswith("vulnerable:"):
                parsed["vulnerable_providers"].append(line.strip())
        
        return parsed
    
    def _parse_provider_info_output(self, output: str) -> Dict[str, Any]:
        """
        Parse provider info output.
        
        Args:
            output: Raw output from provider info scan
            
        Returns:
            Dict[str, Any]: Parsed results
        """
        parsed = {
            "providers": [],
            "exported_count": 0,
            "total_count": 0
        }
        
        if not output:
            return parsed
        
        # Basic parsing of provider information
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if 'authority:' in line.lower():
                parsed["providers"].append(line)
                parsed["total_count"] += 1
                if 'exported' in line.lower():
                    parsed["exported_count"] += 1
        
        return parsed
    
    def _parse_sql_tables_output(self, output: str) -> Dict[str, Any]:
        """
        Parse SQL tables scan output.
        
        Args:
            output: Raw output from SQL tables scan
            
        Returns:
            Dict[str, Any]: Parsed results
        """
        parsed = {
            "tables": [],
            "databases": [],
            "access_info": []
        }
        
        if not output:
            return parsed
        
        # Basic parsing of SQL tables information
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('table:'):
                parsed["tables"].append(line)
            elif line.startswith('database:'):
                parsed["databases"].append(line)
            elif 'accessible' in line.lower():
                parsed["access_info"].append(line)
        
        return parsed
    
    def _analyze_all_results(self, results: Dict[str, Any]) -> bool:
        """
        Analyze all results to determine if vulnerabilities exist.
        
        Args:
            results: All analysis results
            
        Returns:
            bool: True if vulnerabilities are detected
        """
        # Check injection scan results
        injection_scan = results.get("injection_scan", {})
        if injection_scan.get("success", False):
            parsed = injection_scan.get("parsed_results", {})
            if parsed.get("has_vulnerabilities", False):
                return True
        
        # Check provider info for concerning configurations
        provider_info = results.get("provider_info", {})
        if provider_info.get("success", False):
            parsed = provider_info.get("parsed_results", {})
            if parsed.get("exported_count", 0) > 0:
                # Exported providers could indicate potential vulnerabilities
                return True
        
        # Check SQL tables scan for accessible tables
        sql_tables = results.get("sql_tables_scan", {})
        if sql_tables.get("success", False):
            parsed = sql_tables.get("parsed_results", {})
            if parsed.get("tables") or parsed.get("access_info"):
                return True
        
        return False
    
    def _extract_vulnerability_details(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract detailed vulnerability information from results.
        
        Args:
            results: All analysis results
            
        Returns:
            List[Dict[str, Any]]: Detailed vulnerability information
        """
        details = []
        
        # Extract from injection scan
        injection_scan = results.get("injection_scan", {})
        if injection_scan.get("success", False):
            parsed = injection_scan.get("parsed_results", {})
            for vuln_detail in parsed.get("vulnerability_details", []):
                details.append({
                    "source": "injection_scan",
                    "type": vuln_detail.get("type", ""),
                    "evidence": vuln_detail.get("evidence", ""),
                    "severity": "HIGH",
                    "confidence": 0.8
                })
        
        # Extract from provider info
        provider_info = results.get("provider_info", {})
        if provider_info.get("success", False):
            parsed = provider_info.get("parsed_results", {})
            if parsed.get("exported_count", 0) > 0:
                details.append({
                    "source": "provider_info",
                    "type": "exported_provider",
                    "evidence": f"Found {parsed.get('exported_count', 0)} exported providers",
                    "severity": "MEDIUM",
                    "confidence": 0.7
                })
        
        # Extract from SQL tables scan
        sql_tables = results.get("sql_tables_scan", {})
        if sql_tables.get("success", False):
            parsed = sql_tables.get("parsed_results", {})
            if parsed.get("tables"):
                details.append({
                    "source": "sql_tables_scan",
                    "type": "accessible_tables",
                    "evidence": f"Found {len(parsed.get('tables', []))} accessible tables",
                    "severity": "MEDIUM",
                    "confidence": 0.6
                })
        
        return details
    
    def check_drozer_availability(self, drozer) -> bool:
        """
        Check if Drozer is available and functioning.
        
        Args:
            drozer: Drozer instance to check
            
        Returns:
            bool: True if Drozer is available
        """
        if not drozer:
            return False
        
        try:
            # Try connection status first
            if hasattr(drozer, 'get_connection_status'):
                status = drozer.get_connection_status()
                return status.get("connected", False)
            
            # Try a simple test command
            test_result = self._execute_drozer_command(drozer, "list", 5)
            return test_result.get("success", False)
            
        except Exception:
            return False 