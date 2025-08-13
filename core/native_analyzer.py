"""
Native library analysis for Android APKs.

This module provides analysis of native libraries (.so files) within APKs.
"""

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from rich.text import Text

class NativeAnalyzer:
    """
    Analyzer for native libraries in Android APKs.

    This class provides comprehensive analysis of native binaries including:
    - Security hardening features (PIE, NX, RELRO, Stack Canaries)
    - String extraction and analysis
    - Library enumeration and metadata
    - Vulnerability pattern detection

    Attributes:
        apk_path (Path): Path to the APK file
        package_name (str): Android package name
        extracted_libs (List[Path]): List of extracted native libraries
        analysis_results (Dict): Cached analysis results
    """

    def __init__(self, apk_path: str, package_name: str):
        """
        Initialize native analyzer.

        Args:
            apk_path: Path to the APK file
            package_name: Android package name
        """
        self.apk_path = Path(apk_path)
        self.package_name = package_name
        self.extracted_libs: List[Path] = []
        self.analysis_results: Dict = {}
        self.temp_dir: Optional[Path] = None

    def extract_native_libraries(self) -> bool:
        """
        Extract native libraries from APK.

        Returns:
            bool: True if extraction successful, False otherwise
        """
        try:
            # Create temporary directory for extraction
            self.temp_dir = Path(tempfile.mkdtemp(prefix="native_analysis_"))

            logging.debug(f"Extracting native libraries from {self.apk_path}")

            # Use unzip to extract lib/ directory
            extract_cmd = [
                "unzip",
                "-q",
                "-j",
                str(self.apk_path),
                "lib/*/*.so",
                "-d",
                str(self.temp_dir),
            ]

            result = subprocess.run(
                extract_cmd, capture_output=True, text=True, timeout=60
            )

            # Check if any .so files were extracted
            so_files = list(self.temp_dir.glob("*.so"))

            if so_files:
                self.extracted_libs = so_files
                logging.debug(f"Extracted {len(so_files)} native libraries")
                return True
            else:
                logging.debug("No native libraries found in APK")
                return False

        except subprocess.TimeoutExpired:
            logging.error("Native library extraction timed out")
            return False
        except Exception as e:
            logging.error(f"Native library extraction failed: {e}")
            return False

    def analyze_binary_hardening(self, lib_path: Path) -> Dict[str, Union[str, bool]]:
        """
        Analyze binary hardening features using checksec-like analysis.

        Args:
            lib_path: Path to the native library

        Returns:
            Dict containing hardening analysis results
        """
        hardening_info = {
            "library": lib_path.name,
            "pie": False,
            "nx": False,
            "relro": False,
            "canary": False,
            "stripped": False,
            "architecture": "unknown",
            "issues": [],
            "recommendations": [],
        }

        try:
            # Use readelf for binary analysis
            readelf_cmd = ["readelf", "-h", "-l", "-d", str(lib_path)]
            result = subprocess.run(
                readelf_cmd, capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                hardening_info["issues"].append("Failed to analyze binary with readelf")
                return hardening_info

            output = result.stdout.lower()

            # Check for PIE (Position Independent Executable)
            if "type:" in output and "dyn" in output:
                hardening_info["pie"] = True
            else:
                hardening_info["issues"].append("PIE not enabled")
                hardening_info["recommendations"].append(
                    "Enable PIE compilation (-fPIE)"
                )

            # Check for NX bit (No Execute)
            if "gnu_stack" in output and "rwe" not in output:
                hardening_info["nx"] = True
            else:
                hardening_info["issues"].append("NX bit not set")
                hardening_info["recommendations"].append("Enable NX bit protection")

            # Check for RELRO (Relocation Read-Only)
            if "gnu_relro" in output:
                hardening_info["relro"] = True
            else:
                hardening_info["issues"].append("RELRO not enabled")
                hardening_info["recommendations"].append("Enable RELRO (-Wl,-z,relro)")

            # Check for Stack Canaries
            strings_result = subprocess.run(
                ["strings", str(lib_path)], capture_output=True, text=True, timeout=30
            )

            if strings_result.returncode == 0:
                strings_output = strings_result.stdout.lower()
                if (
                    "__stack_chk_fail" in strings_output
                    or "__stack_chk_guard" in strings_output
                ):
                    hardening_info["canary"] = True
                else:
                    hardening_info["issues"].append("Stack canaries not detected")
                    hardening_info["recommendations"].append(
                        "Enable stack protection (-fstack-protector)"
                    )

            # Check if binary is stripped
            if "section headers:" not in output or ".symtab" not in output:
                hardening_info["stripped"] = True

            # Determine architecture
            if "aarch64" in output or "arm64" in output:
                hardening_info["architecture"] = "arm64"
            elif "arm" in output:
                hardening_info["architecture"] = "arm"
            elif "x86_64" in output or "x86-64" in output:
                hardening_info["architecture"] = "x86_64"
            elif "i386" in output or "80386" in output:
                hardening_info["architecture"] = "x86"

        except subprocess.TimeoutExpired:
            hardening_info["issues"].append("Binary analysis timed out")
        except Exception as e:
            hardening_info["issues"].append(f"Binary analysis failed: {str(e)}")

        return hardening_info

    def extract_strings(
        self, lib_path: Path, min_length: int = 4
    ) -> Dict[str, List[str]]:
        """
        Extract and categorize strings from native library.

        Args:
            lib_path: Path to the native library
            min_length: Minimum string length to extract

        Returns:
            Dict containing categorized strings
        """
        string_categories = {
            "urls": [],
            "file_paths": [],
            "crypto_strings": [],
            "debug_strings": [],
            "api_keys": [],
            "suspicious": [],
            "all_strings": [],
        }

        try:
            # Extract strings using strings command
            strings_cmd = ["strings", "-n", str(min_length), str(lib_path)]
            result = subprocess.run(
                strings_cmd, capture_output=True, text=True, timeout=60
            )

            if result.returncode != 0:
                return string_categories

            strings_list = result.stdout.strip().split("\n")
            string_categories["all_strings"] = strings_list[
                :1000
            ]  # Limit to first 1000

            # Categorize strings
            for string in strings_list:
                string_lower = string.lower()

                # URLs
                if any(
                    proto in string_lower for proto in ["http://", "https://", "ftp://"]
                ):
                    string_categories["urls"].append(string)

                # File paths
                if string.startswith("/") or "\\" in string:
                    string_categories["file_paths"].append(string)

                # Crypto-related strings
                crypto_keywords = [
                    "aes",
                    "des",
                    "rsa",
                    "sha",
                    "md5",
                    "crypto",
                    "cipher",
                    "encrypt",
                    "decrypt",
                    "key",
                    "iv",
                    "salt",
                    "hash",
                ]
                if any(keyword in string_lower for keyword in crypto_keywords):
                    string_categories["crypto_strings"].append(string)

                # Debug strings
                debug_keywords = ["debug", "log", "trace", "error", "warning", "printf"]
                if any(keyword in string_lower for keyword in debug_keywords):
                    string_categories["debug_strings"].append(string)

                # Potential API keys (long alphanumeric strings)
                if len(string) > 20 and string.isalnum():
                    string_categories["api_keys"].append(string)

                # Suspicious patterns
                suspicious_keywords = [
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "auth",
                    "admin",
                    "root",
                    "backdoor",
                    "exploit",
                    "shell",
                    "cmd",
                ]
                if any(keyword in string_lower for keyword in suspicious_keywords):
                    string_categories["suspicious"].append(string)

            # Limit each category to prevent overwhelming output
            for category in string_categories:
                if category != "all_strings":
                    string_categories[category] = string_categories[category][:50]

        except subprocess.TimeoutExpired:
            logging.warning(f"String extraction timed out for {lib_path.name}")
        except Exception as e:
            logging.warning(f"String extraction failed for {lib_path.name}: {e}")

        return string_categories

    def analyze_library_metadata(self, lib_path: Path) -> Dict[str, str]:
        """
        Extract metadata from native library.

        Args:
            lib_path: Path to the native library

        Returns:
            Dict containing library metadata
        """
        metadata = {
            "name": lib_path.name,
            "size": str(lib_path.stat().st_size),
            "architecture": "unknown",
            "compiler": "unknown",
            "build_id": "unknown",
            "dependencies": [],
            "exported_functions": [],
            "imported_functions": [],
        }

        try:
            # Get file info
            file_cmd = ["file", str(lib_path)]
            file_result = subprocess.run(
                file_cmd, capture_output=True, text=True, timeout=30
            )

            if file_result.returncode == 0:
                file_output = file_result.stdout.lower()

                # Determine architecture from file output
                if "aarch64" in file_output:
                    metadata["architecture"] = "arm64"
                elif "arm" in file_output:
                    metadata["architecture"] = "arm"
                elif "x86-64" in file_output:
                    metadata["architecture"] = "x86_64"
                elif "80386" in file_output:
                    metadata["architecture"] = "x86"

            # Get dependencies using readelf
            deps_cmd = ["readelf", "-d", str(lib_path)]
            deps_result = subprocess.run(
                deps_cmd, capture_output=True, text=True, timeout=30
            )

            if deps_result.returncode == 0:
                for line in deps_result.stdout.split("\n"):
                    if "NEEDED" in line and "[" in line and "]" in line:
                        dep = line.split("[")[1].split("]")[0]
                        metadata["dependencies"].append(dep)

            # Get exported symbols
            symbols_cmd = ["readelf", "-s", str(lib_path)]
            symbols_result = subprocess.run(
                symbols_cmd, capture_output=True, text=True, timeout=30
            )

            if symbols_result.returncode == 0:
                exported_funcs = []
                for line in symbols_result.stdout.split("\n"):
                    if "FUNC" in line and "GLOBAL" in line:
                        parts = line.split()
                        if len(parts) > 7:
                            func_name = parts[-1]
                            if func_name and not func_name.startswith("_"):
                                exported_funcs.append(func_name)

                metadata["exported_functions"] = exported_funcs[:20]  # Limit output

        except subprocess.TimeoutExpired:
            logging.warning(f"Metadata extraction timed out for {lib_path.name}")
        except Exception as e:
            logging.warning(f"Metadata extraction failed for {lib_path.name}: {e}")

        return metadata

    def generate_comprehensive_analysis(self) -> Dict[str, Union[str, List, Dict]]:
        """
        Generate comprehensive native library analysis.

        Returns:
            Dict containing complete analysis results
        """
        if not self.extract_native_libraries():
            return {
                "status": "no_native_libs",
                "message": "No native libraries found in APK",
                "libraries": [],
            }

        analysis = {
            "status": "success",
            "total_libraries": len(self.extracted_libs),
            "libraries": [],
            "summary": {
                "hardening_issues": 0,
                "security_concerns": 0,
                "architectures": set(),
                "total_strings": 0,
            },
        }

        for lib_path in self.extracted_libs:
            logging.debug(f"Analyzing native library: {lib_path.name}")

            # Analyze binary hardening
            hardening = self.analyze_binary_hardening(lib_path)

            # Extract strings
            strings = self.extract_strings(lib_path)

            # Get metadata
            metadata = self.analyze_library_metadata(lib_path)

            lib_analysis = {
                "metadata": metadata,
                "hardening": hardening,
                "strings": strings,
                "risk_assessment": self._assess_library_risk(hardening, strings),
            }

            analysis["libraries"].append(lib_analysis)

            # Update summary
            analysis["summary"]["hardening_issues"] += len(hardening["issues"])
            analysis["summary"]["security_concerns"] += len(strings["suspicious"])
            analysis["summary"]["architectures"].add(metadata["architecture"])
            analysis["summary"]["total_strings"] += len(strings["all_strings"])

        # Convert set to list for JSON serialization
        analysis["summary"]["architectures"] = list(
            analysis["summary"]["architectures"]
        )

        return analysis

    def _assess_library_risk(self, hardening: Dict, strings: Dict) -> Dict[str, str]:
        """
        Assess risk level for a native library.

        Args:
            hardening: Hardening analysis results
            strings: String analysis results

        Returns:
            Dict containing risk assessment
        """
        risk_score = 0
        risk_factors = []

        # Hardening issues
        if not hardening["pie"]:
            risk_score += 2
            risk_factors.append("PIE not enabled")

        if not hardening["nx"]:
            risk_score += 2
            risk_factors.append("NX bit not set")

        if not hardening["relro"]:
            risk_score += 1
            risk_factors.append("RELRO not enabled")

        if not hardening["canary"]:
            risk_score += 2
            risk_factors.append("Stack canaries not detected")

        # String-based risks
        if strings["suspicious"]:
            risk_score += len(strings["suspicious"])
            risk_factors.append(
                f"{len(strings['suspicious'])} suspicious strings found"
            )

        if strings["api_keys"]:
            risk_score += len(strings["api_keys"]) * 2
            risk_factors.append(f"{len(strings['api_keys'])} potential API keys found")

        # Determine risk level
        if risk_score >= 8:
            risk_level = "HIGH"
        elif risk_score >= 4:
            risk_level = "MEDIUM"
        elif risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
        }

    def cleanup(self) -> None:
        """Clean up temporary files and directories."""
        try:
            if self.temp_dir and self.temp_dir.exists():
                import shutil

                shutil.rmtree(self.temp_dir)
                logging.debug(
                    f"Cleaned up native analysis temp directory: {self.temp_dir}"
                )
        except Exception as e:
            logging.warning(f"Failed to cleanup native analysis temp files: {e}")

def run_native_analysis(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Run comprehensive native library analysis on the APK.

    Args:
        apk_ctx: APKContext instance

    Returns:
        Tuple containing title and formatted results
    """
    if not apk_ctx.package_name:
        return (
            "Native Binary Analysis",
            Text.from_markup("[red]Error: Package name not available[/red]"),
        )

    try:
        # Initialize native analyzer
        analyzer = NativeAnalyzer(str(apk_ctx.apk_path), apk_ctx.package_name)

        # Generate comprehensive analysis
        analysis = analyzer.generate_comprehensive_analysis()

        # Format results for display
        result = _format_native_results(analysis)

        # Cleanup
        analyzer.cleanup()

        return ("Native Binary Analysis", result)

    except Exception as e:
        logging.error(f"Native analysis failed: {e}")
        return (
            "Native Binary Analysis",
            Text.from_markup(f"[red]Analysis failed: {e}[/red]"),
        )

def _format_native_results(analysis: Dict) -> Text:
    """Format native analysis results for display."""
    output = Text()

    # Header
    output.append("Native Binary Security Analysis\n", style="bold blue")
    output.append("=" * 50 + "\n\n", style="blue")

    if analysis["status"] == "no_native_libs":
        output.append("ℹ️  No native libraries found in APK\n", style="yellow")
        output.append("This is common for pure Java/Kotlin applications.\n")
        return output

    # Summary
    summary = analysis.get("summary", {})
    output.append("Analysis Summary\n", style="bold")
    output.append(f"• Total Libraries: {analysis.get('total_libraries', 0)}\n")
    output.append(f"• Hardening Issues: {summary.get('hardening_issues', 0)}\n")
    output.append(f"• Security Concerns: {summary.get('security_concerns', 0)}\n")
    output.append(f"• Architectures: {', '.join(summary.get('architectures', []))}\n\n")

    # Library details
    libraries = analysis.get("libraries", [])
    if libraries:
        output.append("📚 Library Analysis\n", style="bold")

        for lib in libraries:
            metadata = lib.get("metadata", {})
            hardening = lib.get("hardening", {})
            strings = lib.get("strings", {})
            risk = lib.get("risk_assessment", {})

            # Library header
            output.append(
                f"\n{metadata.get('name', 'Unknown')}\n", style="bold cyan"
            )

            # Basic info
            output.append(
                f"  Architecture: {metadata.get('architecture', 'unknown')}\n"
            )
            output.append(f"  Size: {metadata.get('size', 'unknown')} bytes\n")

            # Risk assessment
            risk_level = risk.get("risk_level", "UNKNOWN")
            risk_color = {
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
                "MINIMAL": "green",
            }.get(risk_level, "white")

            output.append(f"  Risk Level: ", style="bold")
            output.append(f"{risk_level}\n", style=risk_color)

            # Hardening status
            output.append("  Security Hardening:\n", style="bold")
            hardening_checks = [
                ("PIE", hardening.get("pie", False)),
                ("NX", hardening.get("nx", False)),
                ("RELRO", hardening.get("relro", False)),
                ("Canary", hardening.get("canary", False)),
            ]

            for check_name, enabled in hardening_checks:
                status = "" if enabled else "❌"
                color = "green" if enabled else "red"
                output.append(f"    {status} {check_name}\n", style=color)

            # Issues and recommendations
            issues = hardening.get("issues", [])
            if issues:
                output.append("  Issues:\n", style="yellow")
                for issue in issues[:3]:  # Limit to first 3
                    output.append(f"    • {issue}\n", style="yellow")

            # String analysis highlights
            if strings.get("suspicious"):
                output.append(
                    f"  🚨 Suspicious strings: {len(strings['suspicious'])}\n",
                    style="red",
                )

            if strings.get("crypto_strings"):
                output.append(
                    f"  🔐 Crypto-related strings: {len(strings['crypto_strings'])}\n",
                    style="cyan",
                )

            if strings.get("urls"):
                output.append(
                    f"  🌐 URLs found: {len(strings['urls'])}\n", style="cyan"
                )

    # Recommendations
    output.append("\nSecurity Recommendations\n", style="bold green")
    output.append(
        "• Enable all binary hardening features (PIE, NX, RELRO, Stack Canaries)\n"
    )
    output.append("• Review and remove any hardcoded secrets from native code\n")
    output.append("• Strip debug symbols from production binaries\n")
    output.append("• Use compiler security flags during build process\n")
    output.append("• Regularly audit native dependencies for vulnerabilities\n")

    return output
