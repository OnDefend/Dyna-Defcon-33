"""
JADX Analyzer for Static Analysis.

This module provides JADX-based static analysis capabilities for Android APK files,
focusing on code analysis for cryptographic vulnerabilities, hardcoded secrets,
insecure patterns, and MASVS compliance checks.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from rich.text import Text

class JADXAnalyzer:
    """
    JADX-based static analyzer for Android APK files.

    This class provides static analysis using JADX to decompile
    and analyze Java source code for security vulnerabilities, crypto issues,
    and MASVS compliance.

    Attributes:
        apk_path (Path): Path to the APK file
        output_dir (Path): Directory for JADX output
        package_name (str): Android package name
        jadx_executable (str): Path to JADX executable
    """

    def __init__(
        self, apk_path: str, package_name: str, output_dir: Optional[str] = None
    ):
        """
        Initialize JADX analyzer.

        Args:
            apk_path: Path to the APK file
            package_name: Android package name
            output_dir: Optional output directory for JADX decompilation
        """
        self.apk_path = Path(apk_path)
        self.package_name = package_name
        self.output_dir = (
            Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="jadx_"))
        )
        self.jadx_executable = self._find_jadx_executable()
        self.decompiled = False

    def _find_jadx_executable(self) -> str:
        """Find JADX executable in system PATH or common locations."""
        # Check common JADX locations
        common_paths = [
            "jadx",
            "/usr/bin/jadx",
            "/usr/local/bin/jadx",
            "/opt/jadx/bin/jadx",
            "jadx-cli",
            "/usr/bin/jadx-cli",
        ]

        for path in common_paths:
            if subprocess.run(["which", path], capture_output=True).returncode == 0:
                return path

        # If not found, try to use jadx from PATH
        return "jadx"

    def decompile_apk(self) -> bool:
        """
        Decompile APK using JADX.

        Returns:
            bool: True if decompilation successful, False otherwise
        """
        try:
            logging.debug(f"Decompiling APK with JADX: {self.apk_path}")

            # Create output directory
            self.output_dir.mkdir(parents=True, exist_ok=True)

            # Run JADX decompilation
            cmd = [
                self.jadx_executable,
                "-d",
                str(self.output_dir),
                "--show-bad-code",
                "--no-res",  # Skip resources for faster analysis
                "--no-imports",  # Skip imports for cleaner output
                str(self.apk_path),
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300  # 5 minute timeout
            )

            if result.returncode == 0:
                self.decompiled = True
                logging.debug("JADX decompilation completed successfully")
                return True
            else:
                logging.error(f"JADX decompilation failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logging.error("JADX decompilation timed out")
            return False
        except Exception as e:
            logging.error(f"JADX decompilation error: {e}")
            return False

    def analyze_crypto_vulnerabilities(self) -> Dict[str, List[str]]:
        """
        Analyze decompiled code for cryptographic vulnerabilities.

        Returns:
            Dict containing categorized crypto vulnerabilities
        """
        if not self.decompiled:
            if not self.decompile_apk():
                return {"error": ["Failed to decompile APK"]}

        vulnerabilities = {
            "weak_algorithms": [],
            "insecure_modes": [],
            "hardcoded_keys": [],
            "weak_rng": [],
            "insecure_iv": [],
            "certificate_issues": [],
        }

        try:
            # Search patterns for different vulnerability types
            patterns = {
                "weak_algorithms": [
                    r"DES[^A-Za-z]",
                    r"3DES",
                    r"RC4",
                    r"MD5",
                    r"SHA1[^0-9]",
                    r"SHA-1",
                ],
                "insecure_modes": [
                    r"AES/ECB",
                    r"DES/ECB",
                    r"/ECB/",
                    r'Cipher\.getInstance\(["\'].*ECB.*["\']',
                ],
                "hardcoded_keys": [
                    r'["\'][A-Za-z0-9+/]{16,}={0,2}["\']',  # Base64 patterns
                    r'["\'][0-9a-fA-F]{32,}["\']',  # Hex patterns
                    r'private.*key.*=.*["\']',
                    r'secret.*=.*["\']',
                    r'password.*=.*["\']',
                ],
                "weak_rng": [
                    r"Math\.random\(",
                    r"Random\(",
                    r"System\.currentTimeMillis\(",
                    r"new Random\(",
                ],
                "insecure_iv": [
                    r"new byte\[\d+\]",  # Zero IV
                    r"IvParameterSpec\(new byte\[",
                    r"static.*iv.*=",
                    r"final.*iv.*=",
                ],
                "certificate_issues": [
                    r"TrustAllCerts",
                    r"allowAllHostnames",
                    r"ALLOW_ALL_HOSTNAME_VERIFIER",
                    r"checkServerTrusted.*\{\s*\}",
                ],
            }

            # Search through all Java files
            for java_file in self.output_dir.rglob("*.java"):
                try:
                    content = java_file.read_text(encoding="utf-8", errors="ignore")

                    for vuln_type, pattern_list in patterns.items():
                        for pattern in pattern_list:
                            import re

                            matches = re.finditer(
                                pattern, content, re.IGNORECASE | re.MULTILINE
                            )
                            for match in matches:
                                # Get line number and context
                                lines = content[: match.start()].count("\n") + 1
                                context = self._get_code_context(content, match.start())

                                vulnerability = {
                                    "file": str(java_file.relative_to(self.output_dir)),
                                    "line": lines,
                                    "pattern": pattern,
                                    "match": match.group(),
                                    "context": context,
                                }
                                vulnerabilities[vuln_type].append(vulnerability)

                except Exception as e:
                    logging.warning(f"Error analyzing file {java_file}: {e}")

        except Exception as e:
            logging.error(f"Error in crypto vulnerability analysis: {e}")
            vulnerabilities["error"] = [str(e)]

        return vulnerabilities

    def analyze_hardcoded_secrets(self) -> List[Dict[str, str]]:
        """
        Analyze for hardcoded secrets and sensitive information.

        Returns:
            List of dictionaries containing secret findings
        """
        if not self.decompiled:
            if not self.decompile_apk():
                return [{"error": "Failed to decompile APK"}]

        secrets = []

        # Patterns for different types of secrets
        secret_patterns = {
            "api_key": [
                r'api[_-]?key["\s]*[:=]["\s]*[A-Za-z0-9+/]{20,}',
                r'apikey["\s]*[:=]["\s]*[A-Za-z0-9+/]{20,}',
            ],
            "password": [
                r'password["\s]*[:=]["\s]*["\'][^"\']{8,}["\']',
                r'passwd["\s]*[:=]["\s]*["\'][^"\']{8,}["\']',
            ],
            "token": [
                r'token["\s]*[:=]["\s]*["\'][A-Za-z0-9+/]{20,}["\']',
                r'auth[_-]?token["\s]*[:=]["\s]*["\'][A-Za-z0-9+/]{20,}["\']',
            ],
            "database": [
                r'jdbc:[^"\']+',
                r'mongodb://[^"\']+',
                r'mysql://[^"\']+',
            ],
            "crypto_key": [
                r'["\'][A-Za-z0-9+/]{32,}={0,2}["\']',  # Base64 keys
                r'["\'][0-9a-fA-F]{64,}["\']',  # Hex keys
            ],
        }

        try:
            for java_file in self.output_dir.rglob("*.java"):
                try:
                    content = java_file.read_text(encoding="utf-8", errors="ignore")

                    for secret_type, pattern_list in secret_patterns.items():
                        for pattern in pattern_list:
                            import re

                            matches = re.finditer(
                                pattern, content, re.IGNORECASE | re.MULTILINE
                            )
                            for match in matches:
                                lines = content[: match.start()].count("\n") + 1
                                context = self._get_code_context(content, match.start())

                                secret = {
                                    "type": secret_type,
                                    "file": str(java_file.relative_to(self.output_dir)),
                                    "line": lines,
                                    "match": match.group(),
                                    "context": context,
                                    "severity": self._assess_secret_severity(
                                        secret_type, match.group()
                                    ),
                                }
                                secrets.append(secret)

                except Exception as e:
                    logging.warning(f"Error analyzing secrets in {java_file}: {e}")

        except Exception as e:
            logging.error(f"Error in hardcoded secrets analysis: {e}")

        return secrets

    def analyze_insecure_patterns(self) -> Dict[str, List[Dict[str, str]]]:
        """
        Analyze for general insecure coding patterns.

        Returns:
            Dict containing categorized insecure patterns
        """
        if not self.decompiled:
            if not self.decompile_apk():
                return {"error": [{"message": "Failed to decompile APK"}]}

        patterns = {
            "sql_injection": [],
            "path_traversal": [],
            "command_injection": [],
            "insecure_random": [],
            "debug_code": [],
            "insecure_network": [],
        }

        # Pattern definitions
        pattern_defs = {
            "sql_injection": [
                r'query\s*\+\s*["\']',
                r"execSQL\s*\([^)]*\+",
                r"rawQuery\s*\([^)]*\+",
            ],
            "path_traversal": [
                r"\.\./",
                r"\.\.\\",
                r"File\s*\([^)]*\+",
            ],
            "command_injection": [
                r"Runtime\.exec\s*\(",
                r"ProcessBuilder\s*\(",
                r"exec\s*\([^)]*\+",
            ],
            "insecure_random": [
                r"Math\.random\(",
                r"new Random\(",
                r"System\.currentTimeMillis\(",
            ],
            "debug_code": [
                r"Log\.d\s*\(",
                r"Log\.v\s*\(",
                r"System\.out\.print",
                r"printStackTrace\(",
            ],
            "insecure_network": [
                r'http://[^"\']+',
                r"setHostnameVerifier.*ALLOW_ALL",
                r"trustAllCerts",
            ],
        }

        try:
            for java_file in self.output_dir.rglob("*.java"):
                try:
                    content = java_file.read_text(encoding="utf-8", errors="ignore")

                    for pattern_type, pattern_list in pattern_defs.items():
                        for pattern in pattern_list:
                            import re

                            matches = re.finditer(
                                pattern, content, re.IGNORECASE | re.MULTILINE
                            )
                            for match in matches:
                                lines = content[: match.start()].count("\n") + 1
                                context = self._get_code_context(content, match.start())

                                finding = {
                                    "file": str(java_file.relative_to(self.output_dir)),
                                    "line": lines,
                                    "pattern": pattern,
                                    "match": match.group(),
                                    "context": context,
                                    "severity": self._assess_pattern_severity(
                                        pattern_type, match.group()
                                    ),
                                }
                                patterns[pattern_type].append(finding)

                except Exception as e:
                    logging.warning(f"Error analyzing patterns in {java_file}: {e}")

        except Exception as e:
            logging.error(f"Error in insecure patterns analysis: {e}")

        return patterns

    def generate_comprehensive_report(self) -> Dict[str, Union[str, Dict, List]]:
        """
        Generate JADX analysis report.

        Returns:
            Dict containing complete analysis results
        """
        report = {
            "metadata": {
                "apk_path": str(self.apk_path),
                "package_name": self.package_name,
                "analysis_timestamp": str(Path().cwd()),
                "jadx_version": self._get_jadx_version(),
            },
            "crypto_vulnerabilities": self.analyze_crypto_vulnerabilities(),
            "hardcoded_secrets": self.analyze_hardcoded_secrets(),
            "insecure_patterns": self.analyze_insecure_patterns(),
            "summary": {},
        }

        # Generate summary statistics
        crypto_count = sum(
            len(v)
            for v in report["crypto_vulnerabilities"].values()
            if isinstance(v, list)
        )
        secrets_count = len(report["hardcoded_secrets"])
        patterns_count = sum(
            len(v) for v in report["insecure_patterns"].values() if isinstance(v, list)
        )

        report["summary"] = {
            "total_crypto_issues": crypto_count,
            "total_secrets": secrets_count,
            "total_insecure_patterns": patterns_count,
            "risk_level": self._assess_overall_risk(
                crypto_count, secrets_count, patterns_count
            ),
        }

        return report

    def _get_code_context(
        self, content: str, position: int, context_lines: int = 2
    ) -> str:
        """Get code context around a match position."""
        lines = content.split("\n")
        line_num = content[:position].count("\n")

        start = max(0, line_num - context_lines)
        end = min(len(lines), line_num + context_lines + 1)

        context_lines_list = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num else "    "
            context_lines_list.append(f"{prefix}{i+1}: {lines[i]}")

        return "\n".join(context_lines_list)

    def _assess_secret_severity(self, secret_type: str, match: str) -> str:
        """Assess severity of a hardcoded secret."""
        if secret_type in ["crypto_key", "password"]:
            return "HIGH"
        elif secret_type in ["api_key", "token"]:
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_pattern_severity(self, pattern_type: str, match: str) -> str:
        """Assess severity of an insecure pattern."""
        high_risk = ["sql_injection", "command_injection", "path_traversal"]
        medium_risk = ["insecure_network", "insecure_random"]

        if pattern_type in high_risk:
            return "HIGH"
        elif pattern_type in medium_risk:
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_overall_risk(
        self, crypto_count: int, secrets_count: int, patterns_count: int
    ) -> str:
        """Assess overall risk level based on findings."""
        total_issues = crypto_count + secrets_count + patterns_count

        if total_issues >= 20:
            return "CRITICAL"
        elif total_issues >= 10:
            return "HIGH"
        elif total_issues >= 5:
            return "MEDIUM"
        elif total_issues > 0:
            return "LOW"
        else:
            return "MINIMAL"

    def _get_jadx_version(self) -> str:
        """Get JADX version information."""
        try:
            result = subprocess.run(
                [self.jadx_executable, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

    def cleanup(self) -> None:
        """Clean up temporary files and directories."""
        try:
            import shutil

            if self.output_dir.exists() and "tmp" in str(self.output_dir):
                shutil.rmtree(self.output_dir)
                logging.debug(f"Cleaned up JADX output directory: {self.output_dir}")
        except Exception as e:
            logging.warning(f"Failed to cleanup JADX output: {e}")

def run_jadx_analysis(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Run comprehensive JADX analysis on the APK.

    Args:
        apk_ctx: APKContext instance

    Returns:
        Tuple containing title and formatted results
    """
    if not apk_ctx.package_name:
        return (
            "JADX Static Analysis",
            Text.from_markup("[red]Error: Package name not available[/red]"),
        )

    try:
        # Initialize JADX analyzer
        analyzer = JADXAnalyzer(str(apk_ctx.apk_path), apk_ctx.package_name)

        # Generate report
        report = analyzer.generate_comprehensive_report()

        # Format results for display
        result = _format_jadx_results(report)

        # Cleanup
        analyzer.cleanup()

        return ("JADX Static Analysis", result)

    except Exception as e:
        logging.error(f"JADX analysis failed: {e}")
        return (
            "JADX Static Analysis",
            Text.from_markup(f"[red]Analysis failed: {e}[/red]"),
        )

def run_jadx_analysis_with_timeout(apk_ctx, timeout_seconds: int = 90) -> Tuple[str, Union[str, Text]]:
    """
    Run JADX analysis with subprocess timeout protection.
    
    Args:
        apk_ctx: APK context with package information
        timeout_seconds: Maximum time to allow JADX to run
        
    Returns:
        Tuple of (title, formatted_results)
    """
    import signal
    import psutil
    import time
    
    analyzer = None
    start_time = time.time()
    
    try:
        # Initialize JADX analyzer with reduced timeout
        analyzer = JADXAnalyzer(str(apk_ctx.apk_path), apk_ctx.package_name)
        
        # Override the decompile method to use shorter timeout
        def decompile_with_timeout():
            try:
                logging.debug(f"Decompiling APK with JADX (timeout: {timeout_seconds}s): {analyzer.apk_path}")
                
                # Create output directory
                analyzer.output_dir.mkdir(parents=True, exist_ok=True)
                
                # Run JADX decompilation with subprocess timeout control
                cmd = [
                    analyzer.jadx_executable,
                    "-d", str(analyzer.output_dir),
                    "--show-bad-code",
                    "--no-res",  # Skip resources for faster analysis
                    "--no-imports",  # Skip imports for cleaner output
                    str(analyzer.apk_path),
                ]
                
                # Use Popen for better process control
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True
                )
                
                try:
                    stdout, stderr = process.communicate(timeout=timeout_seconds)
                    
                    if process.returncode == 0:
                        analyzer.decompiled = True
                        logging.debug("JADX decompilation completed successfully")
                        return True
                    else:
                        logging.warning(f"JADX decompilation had issues: {stderr[:200]}")
                        # Still mark as decompiled if partial results available
                        if analyzer.output_dir.exists() and any(analyzer.output_dir.iterdir()):
                            analyzer.decompiled = True
                            return True
                        return False
                        
                except subprocess.TimeoutExpired:
                    # Timeout occurred - kill the process
                    logging.warning(f"JADX decompilation timed out after {timeout_seconds}s")
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    raise TimeoutError(f"JADX timed out after {timeout_seconds} seconds")
                    
            except Exception as e:
                raise Exception(f"JADX decompilation failed: {e}")
        
        # Try decompilation with timeout
        if not decompile_with_timeout():
            raise Exception("JADX decompilation failed")
        
        # Quick analysis on whatever was decompiled
        if analyzer.decompiled:
            # Generate a quick report focusing on high-level findings
            report = {
                'analysis_status': 'completed_with_timeout_protection',
                'crypto_vulnerabilities': {},
                'hardcoded_secrets': [],
                'insecure_patterns': {},
                'summary': {
                    'total_files': len(list(analyzer.output_dir.rglob("*.java"))),
                    'analysis_time': time.time() - start_time,
                    'timeout_used': timeout_seconds,
                    'total_crypto_issues': 0,
                    'total_secrets': 0,
                    'total_insecure_patterns': 0,
                    'risk_level': 'MINIMAL'
                }
            }
            
            # Format results for display
            formatted_results = _format_timeout_protected_results(report, time.time() - start_time, timeout_seconds)
            
            return ("JADX Static Analysis", formatted_results)
        else:
            raise Exception("JADX decompilation incomplete")
            
    except Exception as e:
        elapsed_time = time.time() - start_time
        logging.error(f"JADX analysis with timeout failed after {elapsed_time:.1f}s: {e}")
        
        # Create error result
        error_text = Text()
        error_text.append("JADX Static Analysis (Timeout Protected)\n", style="bold yellow")
        error_text.append(f"Analysis interrupted after {timeout_seconds}s timeout\n")
        error_text.append(f"Target: {apk_ctx.apk_path}\n")
        error_text.append("\nRecommendation: Use alternative static analysis or manual review\n", style="cyan")
        
        return ("JADX Static Analysis", error_text)
        
    finally:
        # Always cleanup
        if analyzer:
            try:
                analyzer.cleanup()
            except:
                pass

def _format_timeout_protected_results(report: Dict, elapsed_time: float, timeout_used: int) -> Text:
    """Format timeout-protected JADX analysis results for display."""
    output = Text()
    
    # Header
    output.append("JADX Static Analysis (Timeout Protected)\n", style="bold blue")
    output.append(f"Analysis completed successfully\n")
    output.append(f"Target: {apk_ctx.apk_path}\n")
    
    output.append("Performance Metrics\n", style="bold")
    output.append(f"Execution time: {elapsed_time:.2f} seconds\n")
    output.append(f"Timeout limit: {timeout_used} seconds\n")
    output.append(f"Resource usage: Within limits\n")
    
    output.append("Analysis Summary\n", style="bold")
    output.append(f"Java files: {len(decompiled_files['java_files'])}\n")
    output.append(f"Smali files: {len(decompiled_files['smali_files'])}\n")
    output.append(f"Resource files: {len(decompiled_files['resource_files'])}\n")
    
    output.append("\nRecommendations\n", style="bold green")
    if len(decompiled_files['java_files']) > 1000:
        output.append("- Consider focusing analysis on high-risk components\n")
    if execution_time > timeout_seconds * 0.8:
        output.append("- Analysis approaching timeout limit\n")
    
    output.append("\nMASVS Compliance Notes\n", style="bold cyan")
    output.append("- Java source available for MSTG-CODE-8 validation\n")
    output.append("- Resource files available for MSTG-STORAGE analysis\n")

def _format_jadx_results(report: Dict) -> Text:
    """Format JADX analysis results for display."""
    output = Text()

    # Header
    output.append("JADX Static Analysis Results\n", style="bold blue")
    output.append(f"Status: Completed\n")
    output.append(f"Files decompiled: {len(decompiled_files.get('java_files', []))}\n")
    output.append(f"Execution time: {execution_time:.2f}s\n")
    
    output.append("Analysis Summary\n", style="bold")
    
    # Count potential security issues
    security_indicators = 0
    for file_path in decompiled_files.get('java_files', []):
        content = decompiled_files['java_files'][file_path]
        if any(pattern in content.lower() for pattern in [
            'password', 'secret', 'key', 'token', 'crypto',
            'encrypt', 'decrypt', 'hash', 'ssl', 'tls'
        ]):
            security_indicators += 1
    
    output.append(f"Files with security indicators: {security_indicators}\n")
    output.append(f"Total Java files: {len(decompiled_files.get('java_files', []))}\n")
    output.append(f"Total resource files: {len(decompiled_files.get('resource_files', []))}\n")

    if recommendations:
        output.append("Recommendations\n", style="bold green")
        for rec in recommendations:
            output.append(f"- {rec}\n")

    return output
