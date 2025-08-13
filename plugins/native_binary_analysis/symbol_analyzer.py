"""
Symbol Analyzer Module

Specialized analyzer for symbol table analysis in native binary libraries.
Provides comprehensive symbol analysis, dangerous function detection,
and security assessment capabilities.

Features:
- Symbol table extraction and analysis
- Dangerous function detection with 100+ patterns
- Cryptographic function identification
- Network function analysis
- File operation security assessment
- Debug symbol analysis
- Import/export function enumeration
- Security scoring with evidence-based confidence
- vulnerability reporting
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
import yaml
import shutil
from dataclasses import asdict

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import BinaryAnalysisError, safe_execute
from .data_structures import (
    SymbolAnalysis, 
    NativeBinaryVulnerability,
    VulnerabilitySeverity
)
from .confidence_calculator import BinaryConfidenceCalculator

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

class SymbolAnalyzer:
    """
    Advanced symbol table analyzer for native binary libraries.
    
    Analyzes symbol tables, function imports/exports, and identifies
    potentially dangerous or interesting functions with security implications.
    """
    
    def __init__(self, context: AnalysisContext, confidence_calculator: BinaryConfidenceCalculator, logger: logging.Logger):
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        self.patterns = self._load_symbol_patterns()
        
        # Available analysis tools
        self.available_tools = self._check_available_tools()
        
        # Pre-compile function patterns for performance
        self._function_patterns = {}
        self._compile_function_patterns()
    
    def _load_symbol_patterns(self) -> Dict:
        """Load symbol analysis patterns from YAML configuration."""
        try:
            pattern_file = Path(__file__).parent / "binary_patterns_config.yaml"
            if not pattern_file.exists():
                self.logger.warning(f"Pattern file not found: {pattern_file}")
                return {}
            
            with open(pattern_file, 'r') as f:
                config = yaml.safe_load(f)
                return {
                    'dangerous_functions': config.get('dangerous_functions', {}),
                    'crypto_functions': config.get('crypto_functions', {}),
                    'network_functions': config.get('network_functions', {}),
                    'file_operations': config.get('file_operations', {}),
                    'registry_operations': config.get('registry_operations', {})
                }
        except Exception as e:
            self.logger.error(f"Failed to load symbol patterns: {e}")
            return {}
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """Check availability of binary analysis tools."""
        tools = {
            'nm': shutil.which('nm') is not None,
            'objdump': shutil.which('objdump') is not None,
            'readelf': shutil.which('readelf') is not None,
            'strings': shutil.which('strings') is not None
        }
        
        available_count = sum(tools.values())
        self.logger.info(f"Available symbol analysis tools: {available_count}/4")
        
        return tools
    
    def _compile_function_patterns(self):
        """Pre-compile function name patterns for improved performance."""
        try:
            for category, subcategories in self.patterns.items():
                if isinstance(subcategories, dict):
                    compiled_category = {}
                    for subcategory, functions in subcategories.items():
                        if isinstance(functions, list):
                            # Create regex patterns for function names
                            compiled_patterns = []
                            for func_name in functions:
                                try:
                                    # Create pattern that matches function name with optional decorations
                                    pattern = rf'\b{re.escape(func_name)}\b'
                                    compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
                                except re.error as e:
                                    self.logger.warning(f"Invalid function pattern '{func_name}': {e}")
                            compiled_category[subcategory] = compiled_patterns
                    self._function_patterns[category] = compiled_category
        except Exception as e:
            self.logger.error(f"Failed to compile function patterns: {e}")
    
    def analyze(self, lib_path: Path) -> SymbolAnalysis:
        """
        Perform comprehensive symbol analysis on native binary.
        
        Args:
            lib_path: Path to the native library file
            
        Returns:
            SymbolAnalysis with symbol information and security assessment
        """
        self.logger.info(f"Starting symbol analysis for: {lib_path.name}")
        
        analysis = SymbolAnalysis(library_name=lib_path.name)
        
        try:
            # Extract symbol information using available tools
            symbols_data = self._extract_symbols(lib_path)
            
            if not symbols_data:
                self.logger.warning(f"No symbols extracted from {lib_path}")
                return analysis
            
            # Analyze different function categories
            analysis.dangerous_functions = self._analyze_dangerous_functions(symbols_data)
            analysis.crypto_functions = self._analyze_crypto_functions(symbols_data)
            analysis.network_functions = self._analyze_network_functions(symbols_data)
            analysis.file_operations = self._analyze_file_operations(symbols_data)
            analysis.debug_symbols = self._analyze_debug_symbols(symbols_data)
            analysis.imported_libraries = self._extract_imported_libraries(lib_path)
            analysis.exported_functions = self._extract_exported_functions(symbols_data)
            
            # Calculate symbol statistics
            analysis.symbol_count = len(symbols_data.get('all_symbols', []))
            analysis.stripped_symbols = self._check_stripped_symbols(symbols_data)
            
            # Calculate security score
            analysis.security_score = self._calculate_security_score(analysis)
            
            # Generate vulnerabilities based on findings
            analysis.vulnerabilities = self._generate_vulnerabilities(analysis, lib_path)
            
            self.logger.info(f"Symbol analysis completed for {lib_path.name}: "
                           f"Symbols = {analysis.symbol_count}, "
                           f"Dangerous = {len(analysis.dangerous_functions)}, "
                           f"Security Score = {analysis.security_score:.1f}")
            
        except Exception as e:
            self.logger.error(f"Symbol analysis failed for {lib_path}: {e}")
            raise BinaryAnalysisError(f"Symbol analysis failed: {e}")
        
        return analysis
    
    def _extract_symbols(self, lib_path: Path) -> Dict:
        """Extract symbol information using available tools."""
        symbols_data = {
            'all_symbols': [],
            'imported_symbols': [],
            'exported_symbols': [],
            'debug_symbols': [],
            'dynamic_symbols': []
        }
        
        try:
            # Try different tools based on availability
            if self.available_tools.get('nm'):
                symbols_data.update(self._extract_with_nm(lib_path))
            
            if self.available_tools.get('objdump'):
                symbols_data.update(self._extract_with_objdump(lib_path))
            
            if self.available_tools.get('readelf'):
                symbols_data.update(self._extract_with_readelf(lib_path))
            
            if self.available_tools.get('strings'):
                symbols_data['string_symbols'] = self._extract_with_strings(lib_path)
            
        except Exception as e:
            self.logger.error(f"Failed to extract symbols: {e}")
        
        return symbols_data
    
    def _extract_with_nm(self, lib_path: Path) -> Dict:
        """Extract symbols using nm tool."""
        symbols_data = {}
        
        try:
            # Extract all symbols
            result = subprocess.run(
                ['nm', '-D', '--defined-only', str(lib_path)],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                symbols_data['nm_symbols'] = result.stdout.strip().split('\n')
                symbols_data['all_symbols'] = self._parse_nm_output(result.stdout)
            
            # Extract dynamic symbols
            result = subprocess.run(
                ['nm', '-D', str(lib_path)],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                symbols_data['dynamic_symbols'] = self._parse_nm_output(result.stdout)
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            self.logger.warning(f"nm extraction failed: {e}")
        
        return symbols_data
    
    def _extract_with_objdump(self, lib_path: Path) -> Dict:
        """Extract symbols using objdump tool."""
        symbols_data = {}
        
        try:
            # Extract symbol table
            result = subprocess.run(
                ['objdump', '-t', str(lib_path)],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                symbols_data['objdump_symbols'] = self._parse_objdump_output(result.stdout)
            
            # Extract dynamic symbol table
            result = subprocess.run(
                ['objdump', '-T', str(lib_path)],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                symbols_data['objdump_dynamic'] = self._parse_objdump_output(result.stdout)
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            self.logger.warning(f"objdump extraction failed: {e}")
        
        return symbols_data
    
    def _extract_with_readelf(self, lib_path: Path) -> Dict:
        """Extract symbols using readelf tool."""
        symbols_data = {}
        
        try:
            # Extract symbol table
            result = subprocess.run(
                ['readelf', '-s', str(lib_path)],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                symbols_data['readelf_symbols'] = self._parse_readelf_output(result.stdout)
            
            # Extract dynamic symbols
            result = subprocess.run(
                ['readelf', '--dyn-syms', str(lib_path)],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                symbols_data['readelf_dynamic'] = self._parse_readelf_output(result.stdout)
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            self.logger.warning(f"readelf extraction failed: {e}")
        
        return symbols_data
    
    def _extract_with_strings(self, lib_path: Path) -> List[str]:
        """Extract readable strings from binary."""
        try:
            result = subprocess.run(
                ['strings', '-n', '4', str(lib_path)],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return [s.strip() for s in result.stdout.split('\n') if s.strip()]
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            self.logger.warning(f"strings extraction failed: {e}")
        
        return []
    
    def _parse_nm_output(self, output: str) -> List[str]:
        """Parse nm tool output to extract symbol names."""
        symbols = []
        for line in output.split('\n'):
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 3:
                    symbol_name = parts[-1]  # Symbol name is usually the last part
                    symbols.append(symbol_name)
        return symbols
    
    def _parse_objdump_output(self, output: str) -> List[str]:
        """Parse objdump output to extract symbol names."""
        symbols = []
        for line in output.split('\n'):
            if line.strip() and not line.startswith('SYMBOL TABLE'):
                parts = line.strip().split()
                if len(parts) >= 6:  # objdump format has multiple columns
                    symbol_name = parts[-1]
                    symbols.append(symbol_name)
        return symbols
    
    def _parse_readelf_output(self, output: str) -> List[str]:
        """Parse readelf output to extract symbol names."""
        symbols = []
        in_symbol_table = False
        
        for line in output.split('\n'):
            if 'Symbol table' in line:
                in_symbol_table = True
                continue
            
            if in_symbol_table and line.strip():
                parts = line.strip().split()
                if len(parts) >= 8:  # readelf format
                    symbol_name = parts[-1]
                    symbols.append(symbol_name)
        
        return symbols
    
    def _analyze_dangerous_functions(self, symbols_data: Dict) -> List[str]:
        """Identify dangerous functions in the symbol table."""
        dangerous_found = []
        all_symbols = self._get_all_symbols(symbols_data)
        
        try:
            if 'dangerous_functions' in self._function_patterns:
                for category, patterns in self._function_patterns['dangerous_functions'].items():
                    for pattern in patterns:
                        for symbol in all_symbols:
                            if pattern.search(symbol):
                                dangerous_found.append(f"{symbol} ({category})")
            
            return list(dict.fromkeys(dangerous_found))  # Remove duplicates
            
        except Exception as e:
            self.logger.error(f"Failed to analyze dangerous functions: {e}")
            return []
    
    def _analyze_crypto_functions(self, symbols_data: Dict) -> List[str]:
        """Identify cryptographic functions in the symbol table."""
        crypto_found = []
        all_symbols = self._get_all_symbols(symbols_data)
        
        try:
            if 'crypto_functions' in self._function_patterns:
                for category, patterns in self._function_patterns['crypto_functions'].items():
                    for pattern in patterns:
                        for symbol in all_symbols:
                            if pattern.search(symbol):
                                crypto_found.append(f"{symbol} ({category})")
            
            return list(dict.fromkeys(crypto_found))
            
        except Exception as e:
            self.logger.error(f"Failed to analyze crypto functions: {e}")
            return []
    
    def _analyze_network_functions(self, symbols_data: Dict) -> List[str]:
        """Identify network-related functions in the symbol table."""
        network_found = []
        all_symbols = self._get_all_symbols(symbols_data)
        
        try:
            if 'network_functions' in self._function_patterns:
                for category, patterns in self._function_patterns['network_functions'].items():
                    for pattern in patterns:
                        for symbol in all_symbols:
                            if pattern.search(symbol):
                                network_found.append(f"{symbol} ({category})")
            
            return list(dict.fromkeys(network_found))
            
        except Exception as e:
            self.logger.error(f"Failed to analyze network functions: {e}")
            return []
    
    def _analyze_file_operations(self, symbols_data: Dict) -> List[str]:
        """Identify file operation functions in the symbol table."""
        file_ops_found = []
        all_symbols = self._get_all_symbols(symbols_data)
        
        try:
            if 'file_operations' in self._function_patterns:
                for category, patterns in self._function_patterns['file_operations'].items():
                    for pattern in patterns:
                        for symbol in all_symbols:
                            if pattern.search(symbol):
                                file_ops_found.append(f"{symbol} ({category})")
            
            return list(dict.fromkeys(file_ops_found))
            
        except Exception as e:
            self.logger.error(f"Failed to analyze file operations: {e}")
            return []
    
    def _analyze_debug_symbols(self, symbols_data: Dict) -> List[str]:
        """Identify debug symbols and debug-related information."""
        debug_symbols = []
        
        try:
            all_symbols = self._get_all_symbols(symbols_data)
            
            # Common debug symbol patterns
            debug_patterns = [
                r'.*\.debug_.*',
                r'.*_debug$',
                r'debug_.*',
                r'.*\.eh_frame.*',
                r'.*\.gdb_index.*',
                r'.*_dwarf.*',
                r'.*\.note\..*'
            ]
            
            compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in debug_patterns]
            
            for symbol in all_symbols:
                for pattern in compiled_patterns:
                    if pattern.match(symbol):
                        debug_symbols.append(symbol)
                        break
            
            return list(dict.fromkeys(debug_symbols))
            
        except Exception as e:
            self.logger.error(f"Failed to analyze debug symbols: {e}")
            return []
    
    def _extract_imported_libraries(self, lib_path: Path) -> List[str]:
        """Extract list of imported libraries."""
        imported_libs = []
        
        try:
            if self.available_tools.get('objdump'):
                result = subprocess.run(
                    ['objdump', '-p', str(lib_path)],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'NEEDED' in line:
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                imported_libs.append(parts[-1])
            
            elif self.available_tools.get('readelf'):
                result = subprocess.run(
                    ['readelf', '-d', str(lib_path)],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'NEEDED' in line:
                            # Extract library name from readelf output
                            match = re.search(r'\[(.*?)\]', line)
                            if match:
                                imported_libs.append(match.group(1))
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            self.logger.warning(f"Failed to extract imported libraries: {e}")
        
        return list(dict.fromkeys(imported_libs))
    
    def _extract_exported_functions(self, symbols_data: Dict) -> List[str]:
        """Extract exported function names."""
        exported_functions = []
        
        try:
            # Get exported symbols from dynamic symbol table
            dynamic_symbols = symbols_data.get('dynamic_symbols', [])
            exported_symbols = symbols_data.get('exported_symbols', [])
            
            # Combine all potential exported symbols
            all_exported = dynamic_symbols + exported_symbols
            
            # Filter for function-like symbols (heuristic approach)
            for symbol in all_exported:
                if self._is_likely_function(symbol):
                    exported_functions.append(symbol)
            
            return list(dict.fromkeys(exported_functions))
            
        except Exception as e:
            self.logger.error(f"Failed to extract exported functions: {e}")
            return []
    
    def _get_all_symbols(self, symbols_data: Dict) -> List[str]:
        """Get all unique symbols from various sources."""
        all_symbols = []
        
        symbol_sources = [
            'all_symbols', 'nm_symbols', 'objdump_symbols', 
            'readelf_symbols', 'dynamic_symbols'
        ]
        
        for source in symbol_sources:
            symbols = symbols_data.get(source, [])
            if isinstance(symbols, list):
                all_symbols.extend(symbols)
        
        return list(dict.fromkeys(all_symbols))
    
    def _is_likely_function(self, symbol_name: str) -> bool:
        """Heuristic to determine if a symbol is likely a function."""
        # Common function name patterns
        function_indicators = [
            symbol_name.endswith('()'),
            '_' in symbol_name and not symbol_name.startswith('_'),
            any(char.islower() for char in symbol_name),
            len(symbol_name) > 3
        ]
        
        # Exclude obvious non-functions
        non_function_indicators = [
            symbol_name.isupper() and len(symbol_name) < 4,
            symbol_name.startswith('.'),
            symbol_name.isdigit(),
            symbol_name in ['main', 'init', 'fini']
        ]
        
        return any(function_indicators) and not any(non_function_indicators)
    
    def _check_stripped_symbols(self, symbols_data: Dict) -> bool:
        """Check if binary has stripped debug symbols."""
        try:
            debug_symbols = symbols_data.get('debug_symbols', [])
            all_symbols = self._get_all_symbols(symbols_data)
            
            # If we have very few symbols relative to binary size, it's likely stripped
            if len(all_symbols) < 10:
                return True
            
            # If no debug symbols found, likely stripped
            if not debug_symbols:
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to check stripped symbols: {e}")
            return False
    
    def _calculate_security_score(self, analysis: SymbolAnalysis) -> float:
        """Calculate security score based on symbol analysis findings."""
        try:
            score = 100.0  # Start with perfect score
            
            # Deduct points for dangerous functions
            dangerous_penalty = len(analysis.dangerous_functions) * 5
            score -= min(dangerous_penalty, 50)  # Cap at 50 points
            
            # Deduct points for weak crypto functions
            weak_crypto_penalty = 0
            for crypto_func in analysis.crypto_functions:
                if any(weak in crypto_func.lower() for weak in ['md5', 'sha1', 'des', 'rc4']):
                    weak_crypto_penalty += 3
            score -= min(weak_crypto_penalty, 30)
            
            # Add points for good practices
            if analysis.debug_symbols:
                score += 5  # Debug symbols available (good for analysis)
            
            if len(analysis.crypto_functions) > 0:
                score += 2  # Uses cryptography (potentially good)
            
            # Ensure score is in valid range
            return max(0.0, min(100.0, score))
            
        except Exception as e:
            self.logger.error(f"Failed to calculate security score: {e}")
            return 50.0  # Default neutral score
    
    def _generate_vulnerabilities(self, analysis: SymbolAnalysis, lib_path: Path) -> List[NativeBinaryVulnerability]:
        """Generate vulnerability findings based on symbol analysis."""
        vulnerabilities = []
        
        try:
            # Generate vulnerabilities for dangerous functions
            if analysis.dangerous_functions:
                vuln = NativeBinaryVulnerability(
                    id=f"DANGEROUS_FUNCTIONS_{lib_path.name}",
                    title="Dangerous Functions Detected",
                    description=f"Library {lib_path.name} contains {len(analysis.dangerous_functions)} "
                               f"potentially dangerous functions that may pose security risks",
                    severity=VulnerabilitySeverity.HIGH if len(analysis.dangerous_functions) > 5 
                            else VulnerabilitySeverity.MEDIUM,
                    masvs_control="MSTG-CODE-8",
                    affected_files=[str(lib_path)],
                    evidence=analysis.dangerous_functions[:10],  # Limit evidence output
                    remediation="Review the usage of dangerous functions and consider safer alternatives. "
                              "Implement proper input validation and bounds checking.",
                    cwe_id="CWE-676",  # Use of Potentially Dangerous Function
                    cvss_score=7.0 if len(analysis.dangerous_functions) > 5 else 5.0,
                    confidence=0.85,  # High confidence for symbol detection
                    context={'dangerous_function_count': len(analysis.dangerous_functions)}
                )
                vulnerabilities.append(vuln)
            
            # Check for weak cryptographic functions
            weak_crypto = [func for func in analysis.crypto_functions 
                          if any(weak in func.lower() for weak in ['md5', 'sha1', 'des', 'rc4'])]
            
            if weak_crypto:
                vuln = NativeBinaryVulnerability(
                    id=f"WEAK_CRYPTO_{lib_path.name}",
                    title="Weak Cryptographic Functions",
                    description=f"Library {lib_path.name} uses weak cryptographic functions: "
                               f"{', '.join(weak_crypto[:5])}",
                    severity=VulnerabilitySeverity.MEDIUM,
                    masvs_control="MSTG-CRYPTO-4",
                    affected_files=[str(lib_path)],
                    evidence=weak_crypto,
                    remediation="Replace weak cryptographic functions with stronger alternatives. "
                              "Use SHA-256 or higher, AES instead of DES/3DES.",
                    cwe_id="CWE-327",  # Use of a Broken or Risky Cryptographic Algorithm
                    cvss_score=6.0,
                    confidence=0.90,
                    context={'weak_crypto_functions': weak_crypto}
                )
                vulnerabilities.append(vuln)
            
            # Check for stripped symbols (information disclosure concern)
            if analysis.stripped_symbols:
                vuln = NativeBinaryVulnerability(
                    id=f"STRIPPED_SYMBOLS_{lib_path.name}",
                    title="Debug Symbols Stripped",
                    description=f"Library {lib_path.name} has debug symbols stripped, "
                               f"which may indicate attempt to hide functionality",
                    severity=VulnerabilitySeverity.LOW,
                    masvs_control="MSTG-RESILIENCE-2",
                    affected_files=[str(lib_path)],
                    evidence=["Minimal symbol table", "No debug information"],
                    remediation="Verify the legitimacy of the library. Stripped symbols may "
                              "indicate malicious intent or obfuscation.",
                    cwe_id="CWE-656",  # Reliance on Security Through Obscurity
                    cvss_score=3.0,
                    confidence=0.70,
                    context={'symbol_count': analysis.symbol_count}
                )
                vulnerabilities.append(vuln)
            
        except Exception as e:
            self.logger.error(f"Failed to generate vulnerabilities: {e}")
        
        return vulnerabilities 