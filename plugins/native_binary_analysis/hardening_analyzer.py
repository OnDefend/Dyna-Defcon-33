"""
Binary Hardening Analyzer Module

Specialized analyzer for binary hardening features and security mechanisms.
Analyzes protection mechanisms like PIE, NX, RELRO, stack canaries, CFI, etc.

Features:
- Comprehensive binary protection analysis
- Security feature detection and scoring
- confidence calculation
- MASVS compliance mapping
- Detailed vulnerability reporting
"""

import logging
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import BinaryAnalysisError, ErrorContext

from .data_structures import (
    BinaryHardeningAnalysis,
    BinaryProtectionLevel,
    BinaryArchitecture,
    NativeBinaryVulnerability,
    VulnerabilitySeverity
)
from .confidence_calculator import BinaryConfidenceCalculator, BinaryAnalysisEvidence

class HardeningAnalyzer:
    """
    Specialized analyzer for binary hardening features.
    
    Analyzes various security mechanisms and protection features in native binaries
    to determine the overall security posture and identify vulnerabilities.
    """
    
    def __init__(self, 
                 context: AnalysisContext,
                 confidence_calculator: BinaryConfidenceCalculator,
                 logger: logging.Logger):
        """
        Initialize hardening analyzer.
        
        Args:
            context: Analysis context
            confidence_calculator: Confidence calculator
            logger: Logger instance
        """
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # Protection mechanisms to analyze
        self.protection_mechanisms = {
            'PIE': self._check_pie_enabled,
            'NX': self._check_nx_enabled,
            'RELRO': self._check_relro_enabled,
            'Stack_Canary': self._check_stack_canary,
            'Fortify': self._check_fortify_enabled,
            'CFI': self._check_cfi_enabled
        }
        
        # Protection level thresholds
        self.protection_thresholds = {
            BinaryProtectionLevel.EXCELLENT: 0.9,
            BinaryProtectionLevel.GOOD: 0.7,
            BinaryProtectionLevel.FAIR: 0.5,
            BinaryProtectionLevel.POOR: 0.3,
            BinaryProtectionLevel.CRITICAL: 0.0
        }
        
        # Vulnerability templates
        self.vulnerability_templates = {
            'no_pie': {
                'id': 'BINARY_NO_PIE',
                'title': 'Position Independent Executable (PIE) Not Enabled',
                'description': 'Binary is not compiled with PIE, making it vulnerable to memory corruption attacks',
                'severity': VulnerabilitySeverity.MEDIUM,
                'masvs_control': 'MSTG-CODE-9',
                'cwe_id': 'CWE-121',
                'remediation': 'Compile with -fPIE -pie flags to enable PIE'
            },
            'no_nx': {
                'id': 'BINARY_NO_NX',
                'title': 'NX Bit Not Enabled',
                'description': 'Binary stack is executable, allowing code injection attacks',
                'severity': VulnerabilitySeverity.HIGH,
                'masvs_control': 'MSTG-CODE-8',
                'cwe_id': 'CWE-119',
                'remediation': 'Enable NX bit protection to prevent stack execution'
            },
            'no_relro': {
                'id': 'BINARY_NO_RELRO',
                'title': 'RELRO Not Enabled',
                'description': 'Binary lacks RELRO protection, making GOT/PLT vulnerable to overwrite attacks',
                'severity': VulnerabilitySeverity.MEDIUM,
                'masvs_control': 'MSTG-CODE-9',
                'cwe_id': 'CWE-119',
                'remediation': 'Compile with -Wl,-z,relro,-z,now flags to enable full RELRO'
            },
            'no_stack_canary': {
                'id': 'BINARY_NO_STACK_CANARY',
                'title': 'Stack Canary Not Enabled',
                'description': 'Binary lacks stack canary protection, vulnerable to buffer overflow attacks',
                'severity': VulnerabilitySeverity.HIGH,
                'masvs_control': 'MSTG-CODE-8',
                'cwe_id': 'CWE-120',
                'remediation': 'Compile with -fstack-protector-strong to enable stack canaries'
            },
            'no_fortify': {
                'id': 'BINARY_NO_FORTIFY',
                'title': 'Fortify Source Not Enabled',
                'description': 'Binary lacks fortified function protection against buffer overflows',
                'severity': VulnerabilitySeverity.MEDIUM,
                'masvs_control': 'MSTG-CODE-8',
                'cwe_id': 'CWE-120',
                'remediation': 'Compile with -D_FORTIFY_SOURCE=2 to enable fortified functions'
            },
            'no_cfi': {
                'id': 'BINARY_NO_CFI',
                'title': 'Control Flow Integrity Not Enabled',
                'description': 'Binary lacks CFI protection against ROP/JOP attacks',
                'severity': VulnerabilitySeverity.MEDIUM,
                'masvs_control': 'MSTG-CODE-9',
                'cwe_id': 'CWE-119',
                'remediation': 'Compile with -flto -fsanitize=cfi flags to enable CFI'
            }
        }
        
        self.logger.info("Initialized hardening analyzer")
    
    def analyze(self, lib_path: Path) -> BinaryHardeningAnalysis:
        """
        Analyze binary hardening features.
        
        Args:
            lib_path: Path to library file
            
        Returns:
            BinaryHardeningAnalysis with results
        """
        try:
            # Initialize analysis result
            analysis = BinaryHardeningAnalysis(
                library_name=lib_path.name,
                architecture=BinaryArchitecture.UNKNOWN,
                pie_enabled=False,
                nx_enabled=False,
                relro_enabled=False,
                canary_enabled=False,
                stripped=False,
                fortify_enabled=False,
                cfi_enabled=False,
                protection_level=BinaryProtectionLevel.CRITICAL
            )
            
            # Detect architecture
            analysis.architecture = self._detect_architecture(lib_path)
            
            # Analyze each protection mechanism
            protection_results = {}
            for mechanism_name, check_function in self.protection_mechanisms.items():
                try:
                    enabled = check_function(lib_path)
                    protection_results[mechanism_name] = enabled
                    
                    # Update analysis object
                    if mechanism_name == 'PIE':
                        analysis.pie_enabled = enabled
                    elif mechanism_name == 'NX':
                        analysis.nx_enabled = enabled
                    elif mechanism_name == 'RELRO':
                        analysis.relro_enabled = enabled
                    elif mechanism_name == 'Stack_Canary':
                        analysis.canary_enabled = enabled
                    elif mechanism_name == 'Fortify':
                        analysis.fortify_enabled = enabled
                    elif mechanism_name == 'CFI':
                        analysis.cfi_enabled = enabled
                    
                except Exception as e:
                    self.logger.warning(f"Error checking {mechanism_name} for {lib_path.name}: {e}")
                    protection_results[mechanism_name] = False
            
            # Check if binary is stripped
            analysis.stripped = self._check_stripped(lib_path)
            
            # Calculate protection score and level
            analysis.protection_score = self._calculate_protection_score(protection_results)
            analysis.protection_level = self._determine_protection_level(analysis.protection_score)
            
            # Generate vulnerabilities for missing protections
            analysis.vulnerabilities = self._generate_vulnerabilities(protection_results, lib_path)
            
            # Generate recommendations
            analysis.recommendations = self._generate_recommendations(protection_results)
            
            # Create evidence for confidence calculation
            evidence = self._create_hardening_evidence(lib_path, protection_results)
            
            # Calculate confidence for each vulnerability
            for vulnerability in analysis.vulnerabilities:
                vulnerability.confidence = self.confidence_calculator.calculate_binary_confidence(
                    vulnerability, evidence
                )
            
            self.logger.debug(f"Hardening analysis completed for {lib_path.name}: "
                            f"score={analysis.protection_score:.2f}, "
                            f"level={analysis.protection_level.value}")
            
            return analysis
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="hardening_analyzer",
                operation="analyze",
                file_path=str(lib_path),
                additional_context={"error": str(e)}
            )
            raise BinaryAnalysisError(f"Hardening analysis failed: {e}", error_context) from e
    
    def _detect_architecture(self, lib_path: Path) -> BinaryArchitecture:
        """
        Detect binary architecture.
        
        Args:
            lib_path: Path to library file
            
        Returns:
            Detected architecture
        """
        try:
            result = subprocess.run(
                ['file', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                if 'aarch64' in output or 'arm64' in output:
                    return BinaryArchitecture.ARM64
                elif 'arm' in output:
                    return BinaryArchitecture.ARM32
                elif 'x86-64' in output or 'x86_64' in output:
                    return BinaryArchitecture.X86_64
                elif 'i386' in output or 'x86' in output:
                    return BinaryArchitecture.X86
                elif 'mips' in output:
                    return BinaryArchitecture.MIPS
            
        except Exception as e:
            self.logger.warning(f"Error detecting architecture for {lib_path.name}: {e}")
        
        return BinaryArchitecture.UNKNOWN
    
    def _check_pie_enabled(self, lib_path: Path) -> bool:
        """Check if PIE is enabled."""
        try:
            result = subprocess.run(
                ['readelf', '-h', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Check for DYN type (indicates PIE)
                if 'Type:' in result.stdout and 'DYN' in result.stdout:
                    return True
            
        except Exception as e:
            self.logger.debug(f"Error checking PIE for {lib_path.name}: {e}")
        
        return False
    
    def _check_nx_enabled(self, lib_path: Path) -> bool:
        """Check if NX bit is enabled."""
        try:
            result = subprocess.run(
                ['readelf', '-l', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Look for GNU_STACK with RWE flags
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'GNU_STACK' in line:
                        # If executable flag is not present, NX is enabled
                        if 'RWE' not in line and 'E' not in line.split()[-1]:
                            return True
            
        except Exception as e:
            self.logger.debug(f"Error checking NX for {lib_path.name}: {e}")
        
        return False
    
    def _check_relro_enabled(self, lib_path: Path) -> bool:
        """Check if RELRO is enabled."""
        try:
            result = subprocess.run(
                ['readelf', '-l', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Look for GNU_RELRO segment
                if 'GNU_RELRO' in result.stdout:
                    return True
            
        except Exception as e:
            self.logger.debug(f"Error checking RELRO for {lib_path.name}: {e}")
        
        return False
    
    def _check_stack_canary(self, lib_path: Path) -> bool:
        """Check if stack canary is enabled."""
        try:
            # Check for stack canary symbols
            result = subprocess.run(
                ['nm', '-D', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                if '__stack_chk_fail' in result.stdout or '__stack_chk_guard' in result.stdout:
                    return True
            
            # Also check strings
            strings_result = subprocess.run(
                ['strings', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if strings_result.returncode == 0:
                if '__stack_chk_fail' in strings_result.stdout:
                    return True
            
        except Exception as e:
            self.logger.debug(f"Error checking stack canary for {lib_path.name}: {e}")
        
        return False
    
    def _check_fortify_enabled(self, lib_path: Path) -> bool:
        """Check if fortify source is enabled."""
        try:
            result = subprocess.run(
                ['nm', '-D', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Look for fortified function symbols
                fortified_functions = ['__memcpy_chk', '__strcpy_chk', '__strcat_chk', 
                                    '__sprintf_chk', '__snprintf_chk']
                
                for func in fortified_functions:
                    if func in result.stdout:
                        return True
            
        except Exception as e:
            self.logger.debug(f"Error checking fortify for {lib_path.name}: {e}")
        
        return False
    
    def _check_cfi_enabled(self, lib_path: Path) -> bool:
        """Check if CFI is enabled."""
        try:
            result = subprocess.run(
                ['nm', '-D', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Look for CFI symbols
                if '__cfi_check' in result.stdout or '__cfi_slowpath' in result.stdout:
                    return True
            
            # Also check strings
            strings_result = subprocess.run(
                ['strings', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if strings_result.returncode == 0:
                if '__cfi_check' in strings_result.stdout:
                    return True
            
        except Exception as e:
            self.logger.debug(f"Error checking CFI for {lib_path.name}: {e}")
        
        return False
    
    def _check_stripped(self, lib_path: Path) -> bool:
        """Check if binary is stripped."""
        try:
            result = subprocess.run(
                ['file', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return 'stripped' in result.stdout.lower()
            
        except Exception as e:
            self.logger.debug(f"Error checking stripped status for {lib_path.name}: {e}")
        
        return False
    
    def _calculate_protection_score(self, protection_results: Dict[str, bool]) -> float:
        """
        Calculate overall protection score.
        
        Args:
            protection_results: Dictionary of protection mechanism results
            
        Returns:
            Protection score (0.0 to 100.0)
        """
        # Weight different protection mechanisms
        weights = {
            'PIE': 15.0,
            'NX': 25.0,
            'RELRO': 15.0,
            'Stack_Canary': 25.0,
            'Fortify': 10.0,
            'CFI': 10.0
        }
        
        total_score = 0.0
        total_weight = sum(weights.values())
        
        for mechanism, enabled in protection_results.items():
            if enabled:
                total_score += weights.get(mechanism, 0.0)
        
        return (total_score / total_weight) * 100.0
    
    def _determine_protection_level(self, score: float) -> BinaryProtectionLevel:
        """
        Determine protection level based on score.
        
        Args:
            score: Protection score (0.0 to 100.0)
            
        Returns:
            BinaryProtectionLevel enum
        """
        normalized_score = score / 100.0
        
        for level, threshold in self.protection_thresholds.items():
            if normalized_score >= threshold:
                return level
        
        return BinaryProtectionLevel.CRITICAL
    
    def _generate_vulnerabilities(self, protection_results: Dict[str, bool], lib_path: Path) -> List[NativeBinaryVulnerability]:
        """
        Generate vulnerabilities for missing protections.
        
        Args:
            protection_results: Dictionary of protection mechanism results
            lib_path: Path to library file
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        # Map protection mechanisms to vulnerability templates
        mechanism_to_template = {
            'PIE': 'no_pie',
            'NX': 'no_nx',
            'RELRO': 'no_relro',
            'Stack_Canary': 'no_stack_canary',
            'Fortify': 'no_fortify',
            'CFI': 'no_cfi'
        }
        
        for mechanism, enabled in protection_results.items():
            if not enabled and mechanism in mechanism_to_template:
                template_key = mechanism_to_template[mechanism]
                if template_key in self.vulnerability_templates:
                    template = self.vulnerability_templates[template_key]
                    
                    vulnerability = NativeBinaryVulnerability(
                        id=f"{template['id']}_{lib_path.stem}",
                        title=template['title'],
                        description=template['description'],
                        severity=template['severity'],
                        masvs_control=template['masvs_control'],
                        affected_files=[str(lib_path)],
                        evidence=[f"Protection mechanism '{mechanism}' not enabled"],
                        remediation=template['remediation'],
                        cwe_id=template['cwe_id'],
                        context={'protection_mechanism': mechanism, 'library': lib_path.name}
                    )
                    
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _generate_recommendations(self, protection_results: Dict[str, bool]) -> List[str]:
        """
        Generate security recommendations.
        
        Args:
            protection_results: Dictionary of protection mechanism results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if not protection_results.get('PIE', False):
            recommendations.append("Enable PIE (Position Independent Executable) by compiling with -fPIE -pie")
        
        if not protection_results.get('NX', False):
            recommendations.append("Enable NX bit protection to prevent stack execution")
        
        if not protection_results.get('RELRO', False):
            recommendations.append("Enable RELRO protection by compiling with -Wl,-z,relro,-z,now")
        
        if not protection_results.get('Stack_Canary', False):
            recommendations.append("Enable stack canary protection with -fstack-protector-strong")
        
        if not protection_results.get('Fortify', False):
            recommendations.append("Enable fortify source protection with -D_FORTIFY_SOURCE=2")
        
        if not protection_results.get('CFI', False):
            recommendations.append("Enable Control Flow Integrity with -flto -fsanitize=cfi")
        
        return recommendations
    
    def _create_hardening_evidence(self, lib_path: Path, protection_results: Dict[str, bool]) -> BinaryAnalysisEvidence:
        """
        Create evidence for confidence calculation.
        
        Args:
            lib_path: Path to library file
            protection_results: Dictionary of protection mechanism results
            
        Returns:
            BinaryAnalysisEvidence for confidence calculation
        """
        evidence = BinaryAnalysisEvidence()
        
        # Basic binary properties
        evidence.binary_size = lib_path.stat().st_size
        evidence.library_type = "native"
        evidence.file_location = "lib"
        
        # Analysis methods used
        evidence.analysis_methods = ["static_analysis", "binary_analysis", "protection_analysis"]
        evidence.analysis_tools = ["readelf", "nm", "strings", "file"]
        evidence.analysis_depth = "medium"
        
        # Validation sources
        evidence.static_analysis = True
        evidence.symbol_analysis = True
        
        # Pattern consistency based on protection mechanisms
        enabled_count = sum(1 for enabled in protection_results.values() if enabled)
        total_count = len(protection_results)
        evidence.pattern_consistency = enabled_count / total_count if total_count > 0 else 0.0
        
        return evidence 