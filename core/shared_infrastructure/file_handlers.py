#!/usr/bin/env python3
"""
Shared File Handling Utilities

Consolidated file operations and utilities used across multiple AODS plugins.
Provides safe, efficient, and standardized file handling capabilities.

Features:
- Safe file reading with encoding detection and error handling
- APK content extraction and file discovery utilities
- Binary file detection and string extraction
- File type categorization and validation
- Performance-optimized operations with size limits
- Cross-platform path handling and normalization
"""

import os
import re
import logging
import mimetypes
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Any, Generator
from pathlib import Path
import zipfile
import tempfile
from collections import defaultdict

logger = logging.getLogger(__name__)

class FileTypeDetector:
    """Advanced file type detection and categorization."""
    
    # File extension mappings for categorization
    SOURCE_CODE_EXTENSIONS = {
        '.java', '.kt', '.js', '.ts', '.dart', '.py', '.cpp', '.c', '.h',
        '.swift', '.m', '.mm', '.scala', '.go', '.rs', '.smali'
    }
    
    RESOURCE_EXTENSIONS = {
        '.xml', '.json', '.yaml', '.yml', '.properties', '.txt', '.csv',
        '.html', '.htm', '.css', '.scss', '.less'
    }
    
    CONFIG_EXTENSIONS = {
        '.conf', '.config', '.ini', '.cfg', '.toml', '.env', '.plist', '.gradle'
    }
    
    NATIVE_EXTENSIONS = {
        '.so', '.a', '.dylib', '.dll', '.bin', '.dex', '.odex', '.art'
    }
    
    ARCHIVE_EXTENSIONS = {
        '.apk', '.jar', '.aar', '.zip', '.tar', '.gz', '.bz2'
    }
    
    MEDIA_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.mp3', '.mp4', '.wav'
    }
    
    @classmethod
    def get_file_category(cls, file_path: str) -> str:
        """
        Categorize file based on extension and path analysis.
        
        Args:
            file_path: File path to categorize
            
        Returns:
            str: File category (SOURCE_CODE, RESOURCE, etc.)
        """
        if not file_path:
            return "UNKNOWN"
        
        path = Path(file_path)
        extension = path.suffix.lower()
        
        if extension in cls.SOURCE_CODE_EXTENSIONS:
            return "SOURCE_CODE"
        elif extension in cls.RESOURCE_EXTENSIONS:
            return "RESOURCE"
        elif extension in cls.CONFIG_EXTENSIONS:
            return "CONFIG"
        elif extension in cls.NATIVE_EXTENSIONS:
            return "NATIVE"
        elif extension in cls.ARCHIVE_EXTENSIONS:
            return "ARCHIVE"
        elif extension in cls.MEDIA_EXTENSIONS:
            return "MEDIA"
        elif 'test' in str(path).lower():
            return "TEST"
        elif 'manifest' in path.name.lower():
            return "MANIFEST"
        else:
            return "OTHER"
    
    @classmethod
    def is_text_file(cls, file_path: str) -> bool:
        """
        Check if file is likely to be a text file.
        
        Args:
            file_path: File path to check
            
        Returns:
            bool: True if file is likely text-based
        """
        category = cls.get_file_category(file_path)
        text_categories = {"SOURCE_CODE", "RESOURCE", "CONFIG", "MANIFEST"}
        return category in text_categories
    
    @classmethod
    def is_binary_file(cls, file_path: str) -> bool:
        """
        Check if file is binary by reading initial bytes.
        
        Args:
            file_path: File path to check
            
        Returns:
            bool: True if file appears to be binary
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if not chunk:
                    return False
                
                # Check for null bytes (common in binary files)
                if b'\x00' in chunk:
                    return True
                
                # Check for high ratio of non-printable characters
                printable = sum(1 for byte in chunk if 32 <= byte <= 126 or byte in (9, 10, 13))
                return (printable / len(chunk)) < 0.7
                
        except Exception:
            return True  # Assume binary if can't read

class SafeFileReader:
    """Safe file reading with encoding detection and error handling."""
    
    DEFAULT_ENCODINGS = ['utf-8', 'utf-16', 'iso-8859-1', 'cp1252']
    MAX_FILE_SIZE_MB = 50  # Default max file size for safety
    
    @classmethod
    def read_text_file(cls, file_path: str, max_size_mb: Optional[int] = None,
                      encoding: Optional[str] = None) -> Optional[str]:
        """
        Safely read text file with encoding detection.
        
        Args:
            file_path: Path to file to read
            max_size_mb: Maximum file size in MB (default: 50MB)
            encoding: Specific encoding to use (auto-detect if None)
            
        Returns:
            Optional[str]: File content or None if reading failed
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return None
            
            # Check file size
            max_size = (max_size_mb or cls.MAX_FILE_SIZE_MB) * 1024 * 1024
            if file_path.stat().st_size > max_size:
                logger.debug(f"Skipping large file: {file_path} ({file_path.stat().st_size} bytes)")
                return None
            
            # Try specific encoding first
            if encoding:
                try:
                    return file_path.read_text(encoding=encoding, errors='ignore')
                except Exception as e:
                    logger.debug(f"Failed to read {file_path} with {encoding}: {e}")
            
            # Auto-detect encoding
            for enc in cls.DEFAULT_ENCODINGS:
                try:
                    return file_path.read_text(encoding=enc, errors='ignore')
                except Exception:
                    continue
            
            # Last resort: read as binary and decode with errors ignored
            try:
                with open(file_path, 'rb') as f:
                    raw_content = f.read()
                    return raw_content.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.debug(f"Failed to read file {file_path}: {e}")
                return None
                
        except Exception as e:
            logger.debug(f"Error reading file {file_path}: {e}")
            return None
    
    @classmethod
    def read_binary_file(cls, file_path: str, max_size_mb: Optional[int] = None) -> Optional[bytes]:
        """
        Safely read binary file.
        
        Args:
            file_path: Path to file to read
            max_size_mb: Maximum file size in MB (default: 50MB)
            
        Returns:
            Optional[bytes]: File content or None if reading failed
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return None
            
            # Check file size
            max_size = (max_size_mb or cls.MAX_FILE_SIZE_MB) * 1024 * 1024
            if file_path.stat().st_size > max_size:
                logger.debug(f"Skipping large binary file: {file_path}")
                return None
            
            return file_path.read_bytes()
            
        except Exception as e:
            logger.debug(f"Error reading binary file {file_path}: {e}")
            return None

class APKFileExtractor:
    """Utilities for extracting and analyzing APK file contents."""
    
    @classmethod
    def extract_files_by_category(cls, apk_path: str, categories: Set[str],
                                max_files: int = 1000) -> Dict[str, List[str]]:
        """
        Extract files from APK by category.
        
        Args:
            apk_path: Path to APK file
            categories: Set of categories to extract (SOURCE_CODE, RESOURCE, etc.)
            max_files: Maximum number of files to extract per category
            
        Returns:
            Dict[str, List[str]]: Mapping of category to list of file paths
        """
        categorized_files = defaultdict(list)
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for file_info in apk_zip.filelist:
                    if len(categorized_files) >= max_files:
                        break
                    
                    filename = file_info.filename
                    if file_info.is_dir():
                        continue
                    
                    category = FileTypeDetector.get_file_category(filename)
                    if category in categories:
                        categorized_files[category].append(filename)
        
        except Exception as e:
            logger.error(f"Failed to extract files from APK {apk_path}: {e}")
        
        return dict(categorized_files)
    
    @classmethod
    def extract_file_content(cls, apk_path: str, file_path: str) -> Optional[str]:
        """
        Extract specific file content from APK.
        
        Args:
            apk_path: Path to APK file
            file_path: Path to file within APK
            
        Returns:
            Optional[str]: File content or None if extraction failed
        """
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if file_path in apk_zip.namelist():
                    raw_content = apk_zip.read(file_path)
                    
                    # Try to decode as text
                    for encoding in SafeFileReader.DEFAULT_ENCODINGS:
                        try:
                            return raw_content.decode(encoding)
                        except UnicodeDecodeError:
                            continue
                    
                    # Fallback to binary representation
                    return raw_content.decode('utf-8', errors='ignore')
        
        except Exception as e:
            logger.debug(f"Failed to extract {file_path} from {apk_path}: {e}")
        
        return None
    
    @classmethod
    def find_files_by_pattern(cls, apk_path: str, patterns: List[str]) -> List[str]:
        """
        Find files in APK matching regex patterns.
        
        Args:
            apk_path: Path to APK file
            patterns: List of regex patterns to match filenames
            
        Returns:
            List[str]: List of matching file paths
        """
        matching_files = []
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for filename in apk_zip.namelist():
                    for pattern in compiled_patterns:
                        if pattern.search(filename):
                            matching_files.append(filename)
                            break
        
        except Exception as e:
            logger.error(f"Failed to search files in APK {apk_path}: {e}")
        
        return matching_files

class DirectoryAnalyzer:
    """Utilities for analyzing directory structures and file collections."""
    
    @classmethod
    def collect_files_recursive(cls, directory: str, extensions: Optional[Set[str]] = None,
                              max_files: int = 5000, max_depth: int = 10) -> List[str]:
        """
        Recursively collect files from directory with filtering.
        
        Args:
            directory: Root directory to scan
            extensions: Set of file extensions to include (None for all)
            max_files: Maximum number of files to collect
            max_depth: Maximum directory depth to traverse
            
        Returns:
            List[str]: List of collected file paths
        """
        collected_files = []
        
        try:
            directory = Path(directory)
            if not directory.exists():
                return collected_files
            
            def _collect_recursive(current_path: Path, current_depth: int):
                if current_depth > max_depth or len(collected_files) >= max_files:
                    return
                
                try:
                    for item in current_path.iterdir():
                        if len(collected_files) >= max_files:
                            break
                        
                        if item.is_file():
                            if extensions is None or item.suffix.lower() in extensions:
                                collected_files.append(str(item))
                        elif item.is_dir() and not item.name.startswith('.'):
                            _collect_recursive(item, current_depth + 1)
                
                except PermissionError:
                    pass  # Skip directories we can't access
            
            _collect_recursive(directory, 0)
        
        except Exception as e:
            logger.error(f"Failed to collect files from {directory}: {e}")
        
        return collected_files
    
    @classmethod
    def analyze_directory_structure(cls, directory: str) -> Dict[str, Any]:
        """
        Analyze directory structure and provide statistics.
        
        Args:
            directory: Directory to analyze
            
        Returns:
            Dict[str, Any]: Directory statistics and analysis
        """
        stats = {
            'total_files': 0,
            'total_directories': 0,
            'files_by_category': defaultdict(int),
            'largest_files': [],
            'total_size_bytes': 0
        }
        
        try:
            directory = Path(directory)
            if not directory.exists():
                return stats
            
            for item in directory.rglob('*'):
                if item.is_file():
                    stats['total_files'] += 1
                    category = FileTypeDetector.get_file_category(str(item))
                    stats['files_by_category'][category] += 1
                    
                    try:
                        size = item.stat().st_size
                        stats['total_size_bytes'] += size
                        
                        # Track largest files
                        stats['largest_files'].append((str(item), size))
                        stats['largest_files'].sort(key=lambda x: x[1], reverse=True)
                        stats['largest_files'] = stats['largest_files'][:10]  # Keep top 10
                    
                    except Exception:
                        pass  # Skip files we can't stat
                
                elif item.is_dir():
                    stats['total_directories'] += 1
        
        except Exception as e:
            logger.error(f"Failed to analyze directory {directory}: {e}")
        
        return stats

class StringExtractor:
    """Utilities for extracting strings from binary files."""
    
    MIN_STRING_LENGTH = 4
    MAX_STRING_LENGTH = 1000
    
    @classmethod
    def extract_strings_from_binary(cls, file_path: str, min_length: Optional[int] = None) -> List[str]:
        """
        Extract ASCII strings from binary file using strings command or Python fallback.
        
        Args:
            file_path: Path to binary file
            min_length: Minimum string length to extract
            
        Returns:
            List[str]: List of extracted strings
        """
        min_len = min_length or cls.MIN_STRING_LENGTH
        
        # Try using system 'strings' command first (more efficient)
        try:
            result = subprocess.run(
                ['strings', '-n', str(min_len), file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                strings = result.stdout.strip().split('\n')
                return [s for s in strings if len(s) >= min_len]
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass  # Fall back to Python implementation
        
        # Python fallback implementation
        return cls._extract_strings_python(file_path, min_len)
    
    @classmethod
    def _extract_strings_python(cls, file_path: str, min_length: int) -> List[str]:
        """Python implementation of string extraction."""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                current_string = ""
                
                for byte in f.read():
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string += chr(byte)
                        if len(current_string) > cls.MAX_STRING_LENGTH:
                            # Truncate very long strings
                            if len(current_string) >= min_length:
                                strings.append(current_string[:cls.MAX_STRING_LENGTH])
                            current_string = ""
                    else:
                        if len(current_string) >= min_length:
                            strings.append(current_string)
                        current_string = ""
                
                # Handle final string
                if len(current_string) >= min_length:
                    strings.append(current_string)
        
        except Exception as e:
            logger.debug(f"Failed to extract strings from {file_path}: {e}")
        
        return strings

class PathUtils:
    """Path manipulation and normalization utilities."""
    
    @classmethod
    def sanitize_path(cls, path: str) -> str:
        """
        Sanitize file path for safe display and logging.
        
        Args:
            path: File path to sanitize
            
        Returns:
            str: Sanitized path
        """
        if not path:
            return "Unknown"
        
        # Normalize path separators
        path = path.replace("\\", "/")
        
        # Remove absolute path prefixes for display
        if path.startswith("/"):
            path = path[1:]
        
        # Limit path length for display
        if len(path) > 60:
            parts = path.split("/")
            if len(parts) > 2:
                path = f"{parts[0]}/.../{parts[-1]}"
            else:
                path = path[:57] + "..."
        
        return path
    
    @classmethod
    def normalize_path(cls, path: str) -> str:
        """
        Normalize path for cross-platform compatibility.
        
        Args:
            path: Path to normalize
            
        Returns:
            str: Normalized path
        """
        return str(Path(path).as_posix())
    
    @classmethod
    def get_relative_path(cls, file_path: str, base_path: str) -> str:
        """
        Get relative path from base directory.
        
        Args:
            file_path: Full file path
            base_path: Base directory path
            
        Returns:
            str: Relative path
        """
        try:
            return str(Path(file_path).relative_to(Path(base_path)))
        except ValueError:
            return file_path  # Return original if not relative

# Export main classes for easy import
__all__ = [
    'FileTypeDetector',
    'SafeFileReader', 
    'APKFileExtractor',
    'DirectoryAnalyzer',
    'StringExtractor',
    'PathUtils'
] 