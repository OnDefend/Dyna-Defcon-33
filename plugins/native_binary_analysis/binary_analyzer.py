"""
Binary Analyzer Module

Core binary analysis functionality for native library extraction and analysis.
Handles APK extraction, native library identification, and basic binary analysis.

Features:
- Native library extraction from APK files
- Binary format analysis
- Architecture detection
- Symbol extraction
- File system security analysis
- error handling
"""

import logging
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import shutil
import os

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import BinaryAnalysisError, ErrorContext

from .data_structures import (
    BinaryExtractionResult,
    BinaryArchitecture,
    BinaryAnalysisConfig
)
from .confidence_calculator import BinaryConfidenceCalculator

class BinaryAnalyzer:
    """
    Core binary analyzer for native library extraction and analysis.
    
    Handles the extraction of native libraries from APK files and provides
    basic binary analysis functionality for other specialized analyzers.
    """
    
    def __init__(self, 
                 context: AnalysisContext,
                 confidence_calculator: BinaryConfidenceCalculator,
                 logger: logging.Logger):
        """
        Initialize binary analyzer.
        
        Args:
            context: Analysis context
            confidence_calculator: Confidence calculator
            logger: Logger instance
        """
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # Analysis configuration
        self.config = BinaryAnalysisConfig(
            max_libraries=context.config.get('max_libraries', 50),
            max_file_size_mb=context.config.get('max_file_size_mb', 100),
            analysis_timeout=context.config.get('analysis_timeout', 300),
            parallel_analysis=context.config.get('parallel_analysis', True),
            max_workers=context.config.get('max_workers', 4)
        )
        
        # Temporary directory for extractions
        self.temp_dir: Optional[Path] = None
        self.extracted_libs: List[Path] = []
        
        # Supported architectures
        self.architecture_patterns = {
            'arm64-v8a': BinaryArchitecture.ARM64,
            'armeabi-v7a': BinaryArchitecture.ARM32,
            'armeabi': BinaryArchitecture.ARM32,
            'x86_64': BinaryArchitecture.X86_64,
            'x86': BinaryArchitecture.X86,
            'mips64': BinaryArchitecture.MIPS,
            'mips': BinaryArchitecture.MIPS
        }
        
        self.logger.info("Initialized binary analyzer")
    
    def extract_native_libraries(self, apk_ctx) -> List[Path]:
        """
        Extract native libraries from APK file.
        
        Args:
            apk_ctx: APK context containing path and metadata
            
        Returns:
            List of extracted native library paths
        """
        try:
            # Create temporary directory for extraction
            self.temp_dir = Path(tempfile.mkdtemp(prefix="aods_binary_"))
            
            # Extract libraries from APK
            extraction_result = self._extract_libraries_from_apk(apk_ctx.apk_path)
            
            if not extraction_result.extracted_libraries:
                self.logger.info("No native libraries found in APK")
                return []
            
            # Filter libraries by size and count limits
            filtered_libs = self._filter_libraries(extraction_result.extracted_libraries)
            
            # Store extracted libraries
            self.extracted_libs = filtered_libs
            
            self.logger.info(f"Successfully extracted {len(filtered_libs)} native libraries")
            return filtered_libs
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="binary_analyzer",
                operation="extract_native_libraries",
                apk_path=Path(apk_ctx.apk_path),
                additional_context={"error": str(e)}
            )
            raise BinaryAnalysisError(f"Failed to extract native libraries: {e}", error_context) from e
    
    def _extract_libraries_from_apk(self, apk_path: Path) -> BinaryExtractionResult:
        """
        Extract native libraries from APK file.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            BinaryExtractionResult with extraction details
        """
        extracted_libs = []
        failed_extractions = []
        architectures = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Find all .so files in lib/ directory
                so_files = [f for f in apk_zip.namelist() if f.startswith('lib/') and f.endswith('.so')]
                
                if not so_files:
                    self.logger.info("No native libraries found in APK")
                    return BinaryExtractionResult(
                        total_libraries=0,
                        extracted_libraries=[],
                        failed_extractions=[],
                        architectures=[]
                    )
                
                # Limit number of libraries to process
                if len(so_files) > self.config.max_libraries:
                    self.logger.info(f"Large APK: Processing only first {self.config.max_libraries} libraries")
                    so_files = so_files[:self.config.max_libraries]
                
                # Extract each library
                for so_file in so_files:
                    try:
                        # Get architecture from path
                        arch = self._detect_architecture_from_path(so_file)
                        if arch not in architectures:
                            architectures.append(arch)
                        
                        # Extract library to temporary directory
                        lib_name = Path(so_file).name
                        lib_path = self.temp_dir / lib_name
                        
                        with apk_zip.open(so_file) as source, open(lib_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                        
                        # Verify extraction
                        if lib_path.exists() and lib_path.stat().st_size > 0:
                            extracted_libs.append(lib_path)
                            self.logger.debug(f"Extracted library: {lib_name}")
                        else:
                            failed_extractions.append(f"Empty extraction: {lib_name}")
                    
                    except Exception as e:
                        failed_extractions.append(f"Failed to extract {so_file}: {str(e)}")
                        self.logger.warning(f"Failed to extract {so_file}: {e}")
                
                return BinaryExtractionResult(
                    total_libraries=len(so_files),
                    extracted_libraries=extracted_libs,
                    failed_extractions=failed_extractions,
                    architectures=architectures
                )
        
        except Exception as e:
            raise BinaryAnalysisError(f"Failed to open APK file: {e}") from e
    
    def _detect_architecture_from_path(self, lib_path: str) -> BinaryArchitecture:
        """
        Detect architecture from library path.
        
        Args:
            lib_path: Library path within APK
            
        Returns:
            Detected architecture
        """
        for arch_name, arch_enum in self.architecture_patterns.items():
            if arch_name in lib_path:
                return arch_enum
        
        return BinaryArchitecture.UNKNOWN
    
    def _filter_libraries(self, libraries: List[Path]) -> List[Path]:
        """
        Filter libraries by size and other criteria.
        
        Args:
            libraries: List of library paths
            
        Returns:
            Filtered list of libraries
        """
        filtered_libs = []
        max_size_bytes = self.config.max_file_size_mb * 1024 * 1024
        
        for lib_path in libraries:
            try:
                # Check file size
                if lib_path.stat().st_size > max_size_bytes:
                    self.logger.info(f"Skipping large library: {lib_path.name} ({lib_path.stat().st_size / 1024 / 1024:.1f}MB)")
                    continue
                
                # Check file accessibility
                if not os.access(lib_path, os.R_OK):
                    self.logger.warning(f"Cannot read library: {lib_path.name}")
                    continue
                
                filtered_libs.append(lib_path)
                
            except Exception as e:
                self.logger.warning(f"Error checking library {lib_path.name}: {e}")
                continue
        
        return filtered_libs
    
    def analyze_binary_format(self, lib_path: Path) -> Dict[str, any]:
        """
        Analyze binary format and basic properties.
        
        Args:
            lib_path: Path to library file
            
        Returns:
            Dictionary with binary format analysis
        """
        analysis = {
            'library_name': lib_path.name,
            'file_size': lib_path.stat().st_size,
            'architecture': BinaryArchitecture.UNKNOWN,
            'format': 'unknown',
            'endianness': 'unknown',
            'entry_point': None,
            'sections': [],
            'symbols': [],
            'imports': [],
            'exports': []
        }
        
        try:
            # Use readelf to analyze ELF format
            result = subprocess.run(
                ['readelf', '-h', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                analysis.update(self._parse_elf_header(result.stdout))
            
            # Get section information
            sections_result = subprocess.run(
                ['readelf', '-S', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if sections_result.returncode == 0:
                analysis['sections'] = self._parse_elf_sections(sections_result.stdout)
            
            # Get symbol information
            symbols_result = subprocess.run(
                ['readelf', '-s', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if symbols_result.returncode == 0:
                analysis['symbols'] = self._parse_elf_symbols(symbols_result.stdout)
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout analyzing binary format for {lib_path.name}")
        except Exception as e:
            self.logger.warning(f"Error analyzing binary format for {lib_path.name}: {e}")
        
        return analysis
    
    def _parse_elf_header(self, header_output: str) -> Dict[str, any]:
        """
        Parse ELF header information.
        
        Args:
            header_output: Output from readelf -h
            
        Returns:
            Dictionary with parsed header information
        """
        header_info = {'format': 'ELF'}
        
        for line in header_output.split('\n'):
            line = line.strip()
            
            if 'Class:' in line:
                if 'ELF64' in line:
                    header_info['class'] = 'ELF64'
                elif 'ELF32' in line:
                    header_info['class'] = 'ELF32'
            
            elif 'Data:' in line:
                if 'little endian' in line:
                    header_info['endianness'] = 'little'
                elif 'big endian' in line:
                    header_info['endianness'] = 'big'
            
            elif 'Machine:' in line:
                if 'AArch64' in line:
                    header_info['architecture'] = BinaryArchitecture.ARM64
                elif 'ARM' in line:
                    header_info['architecture'] = BinaryArchitecture.ARM32
                elif 'X86-64' in line:
                    header_info['architecture'] = BinaryArchitecture.X86_64
                elif 'Intel 80386' in line:
                    header_info['architecture'] = BinaryArchitecture.X86
                elif 'MIPS' in line:
                    header_info['architecture'] = BinaryArchitecture.MIPS
            
            elif 'Entry point address:' in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    header_info['entry_point'] = parts[1].strip()
        
        return header_info
    
    def _parse_elf_sections(self, sections_output: str) -> List[Dict[str, str]]:
        """
        Parse ELF section information.
        
        Args:
            sections_output: Output from readelf -S
            
        Returns:
            List of section dictionaries
        """
        sections = []
        
        for line in sections_output.split('\n'):
            line = line.strip()
            
            # Skip header lines
            if not line or line.startswith('[') or 'Name' in line:
                continue
            
            # Parse section line
            parts = line.split()
            if len(parts) >= 7:
                section = {
                    'name': parts[1] if len(parts) > 1 else '',
                    'type': parts[2] if len(parts) > 2 else '',
                    'address': parts[3] if len(parts) > 3 else '',
                    'offset': parts[4] if len(parts) > 4 else '',
                    'size': parts[5] if len(parts) > 5 else '',
                    'flags': parts[6] if len(parts) > 6 else ''
                }
                sections.append(section)
        
        return sections
    
    def _parse_elf_symbols(self, symbols_output: str) -> List[Dict[str, str]]:
        """
        Parse ELF symbol information.
        
        Args:
            symbols_output: Output from readelf -s
            
        Returns:
            List of symbol dictionaries
        """
        symbols = []
        
        for line in symbols_output.split('\n'):
            line = line.strip()
            
            # Skip header lines
            if not line or 'Num:' in line or 'Value' in line:
                continue
            
            # Parse symbol line
            parts = line.split()
            if len(parts) >= 8:
                symbol = {
                    'value': parts[1] if len(parts) > 1 else '',
                    'size': parts[2] if len(parts) > 2 else '',
                    'type': parts[3] if len(parts) > 3 else '',
                    'bind': parts[4] if len(parts) > 4 else '',
                    'vis': parts[5] if len(parts) > 5 else '',
                    'ndx': parts[6] if len(parts) > 6 else '',
                    'name': parts[7] if len(parts) > 7 else ''
                }
                symbols.append(symbol)
        
        return symbols
    
    def get_binary_strings(self, lib_path: Path) -> List[str]:
        """
        Extract strings from binary file.
        
        Args:
            lib_path: Path to library file
            
        Returns:
            List of extracted strings
        """
        strings = []
        
        try:
            result = subprocess.run(
                ['strings', str(lib_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                strings = [s.strip() for s in result.stdout.split('\n') if s.strip()]
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout extracting strings from {lib_path.name}")
        except Exception as e:
            self.logger.warning(f"Error extracting strings from {lib_path.name}: {e}")
        
        return strings
    
    def cleanup(self):
        """Clean up temporary files and directories."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                self.logger.debug("Cleaned up temporary directory")
            except Exception as e:
                self.logger.warning(f"Error cleaning up temporary directory: {e}")
    
    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup() 