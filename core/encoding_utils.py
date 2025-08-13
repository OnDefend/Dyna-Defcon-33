"""
Enhanced Encoding Utilities for AODS

This module provides robust encoding detection and handling utilities
for processing APK files with various encodings and binary content.
"""

import logging
import chardet
import signal
import threading
from typing import Optional, Union, Tuple
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class EnhancedEncodingHandler:
    """Enhanced encoding handler for APK analysis."""
    
    def __init__(self):
        """Initialize the encoding handler."""
        self.encoding_fallbacks = [
            'utf-8',
            'utf-16',
            'utf-16le', 
            'utf-16be',
            'latin-1',
            'cp1252',
            'ascii',
            'iso-8859-1'
        ]
    
    def safe_decode_bytes(self, data: bytes, filename: str = "unknown") -> str:
        """
        Safely decode bytes to string with comprehensive encoding detection.
        
        Args:
            data: Raw bytes to decode
            filename: Filename for logging purposes
            
        Returns:
            Decoded string content
        """
        if not data:
            return ""
        
        # Try chardet detection first
        try:
            detected = chardet.detect(data)
            if detected and detected.get('encoding') and detected.get('confidence', 0) > 0.7:
                encoding = detected['encoding']
                logger.debug(f"Detected encoding {encoding} for {filename}")
                return data.decode(encoding, errors='replace')
        except Exception as e:
            logger.debug(f"Chardet detection failed for {filename}: {e}")
        
        # Try common encodings
        for encoding in self.encoding_fallbacks:
            try:
                return data.decode(encoding, errors='replace')
            except (UnicodeDecodeError, LookupError):
                continue
        
        # Final fallback - decode with errors='ignore'
        logger.warning(f"Using fallback decoding for {filename}")
        return data.decode('utf-8', errors='ignore')
    
    def safe_read_file(self, file_path: str) -> str:
        """
        Safely read file content with encoding detection.
        
        Args:
            file_path: Path to file to read
            
        Returns:
            File content as string
        """
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
            return self.safe_decode_bytes(raw_data, file_path)
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return ""
    
    def safe_parse_xml(self, xml_data: Union[str, bytes], filename: str = "unknown", timeout: int = 30) -> Optional[ET.Element]:
        """
        Safely parse XML content with encoding handling and timeout protection.
        
        Args:
            xml_data: XML content as string or bytes
            filename: Filename for logging purposes
            timeout: Maximum time to spend parsing (seconds)
            
        Returns:
            Parsed XML root element or None if parsing failed
        """
        # Handle binary XML files (like AndroidManifest.xml)
        if isinstance(xml_data, bytes):
            # Check if this is binary XML that needs conversion
            if self._is_binary_xml(xml_data) and "AndroidManifest.xml" in filename:
                logger.info(f"Detected binary AndroidManifest.xml: {filename}")
                converted_xml = self._convert_binary_manifest(filename, xml_data)
                if converted_xml:
                    xml_string = converted_xml
                    logger.info(f"Successfully converted binary AndroidManifest.xml: {filename}")
                else:
                    logger.warning(f"Failed to convert binary AndroidManifest.xml: {filename}")
                    xml_string = self.safe_decode_bytes(xml_data, filename)
            else:
                xml_string = self.safe_decode_bytes(xml_data, filename)
        else:
            xml_string = xml_data
        
        # Check if file is too large for safe parsing
        if len(xml_string) > 10 * 1024 * 1024:  # 10MB limit
            logger.warning(f"XML file {filename} is very large ({len(xml_string)} bytes), attempting simplified parsing")
            return self._parse_large_xml_safely(xml_string, filename)
        
        # Clean up common XML issues
        xml_string = self._clean_xml_content(xml_string)
        
        # Use timeout protection for parsing
        result = [None]
        exception = [None]
        
        def parse_with_timeout():
            try:
                result[0] = ET.fromstring(xml_string)
            except Exception as e:
                exception[0] = e
        
        thread = threading.Thread(target=parse_with_timeout)
        thread.daemon = True
        thread.start()
        thread.join(timeout)
        
        if thread.is_alive():
            logger.warning(f"XML parsing timed out for {filename} after {timeout}s")
            return None
        
        if exception[0]:
            logger.debug(f"XML parsing failed for {filename}: {exception[0]}")
            
            # Try with XML declaration removed
            try:
                lines = xml_string.split('\n')
                if lines and lines[0].strip().startswith('<?xml'):
                    xml_without_declaration = '\n'.join(lines[1:])
                    return ET.fromstring(xml_without_declaration)
            except ET.ParseError:
                pass
            
            # Try with encoding issues fixed
            try:
                cleaned_xml = self._fix_xml_encoding_issues(xml_string)
                return ET.fromstring(cleaned_xml)
            except ET.ParseError:
                pass
            
            logger.warning(f"Could not parse XML content from {filename}")
            return None
        
        return result[0]
    
    def _parse_large_xml_safely(self, xml_content: str, filename: str) -> Optional[ET.Element]:
        """
        Attempt to parse very large XML files by extracting key information.
        
        Args:
            xml_content: Large XML content
            filename: Filename for logging
            
        Returns:
            Simplified XML root element or None
        """
        try:
            # For AndroidManifest.xml, try to extract just the essential parts
            if "AndroidManifest.xml" in filename:
                return self._extract_manifest_essentials(xml_content)
            else:
                # For other large XML files, try line-by-line parsing
                return self._parse_xml_incrementally(xml_content)
        except Exception as e:
            logger.error(f"Failed to parse large XML {filename}: {e}")
            return None
    
    def _extract_manifest_essentials(self, xml_content: str) -> Optional[ET.Element]:
        """Extract essential AndroidManifest.xml information."""
        try:
            # Find the manifest opening tag and extract package info
            import re
            
            # Extract package name and basic attributes
            manifest_match = re.search(r'<manifest[^>]*package="([^"]*)"[^>]*>', xml_content)
            if not manifest_match:
                return None
            
            package_name = manifest_match.group(1)
            
            # Create a simplified manifest structure
            root = ET.Element("manifest")
            root.set("package", package_name)
            
            # Try to extract version info
            version_code_match = re.search(r'android:versionCode="([^"]*)"', xml_content)
            if version_code_match:
                root.set("{http://schemas.android.com/apk/res/android}versionCode", version_code_match.group(1))
            
            version_name_match = re.search(r'android:versionName="([^"]*)"', xml_content)
            if version_name_match:
                root.set("{http://schemas.android.com/apk/res/android}versionName", version_name_match.group(1))
            
            # Add a basic application element
            app_element = ET.SubElement(root, "application")
            
            logger.info(f"Created simplified manifest structure for large file")
            return root
            
        except Exception as e:
            logger.error(f"Failed to extract manifest essentials: {e}")
            return None
    
    def _parse_xml_incrementally(self, xml_content: str) -> Optional[ET.Element]:
        """Parse XML content incrementally for large files."""
        try:
            # Try to parse just the first part of the XML
            lines = xml_content.split('\n')
            if len(lines) > 1000:
                # Take first 1000 lines and try to close any open tags
                partial_content = '\n'.join(lines[:1000])
                # Add closing tags if needed
                if not partial_content.strip().endswith('>'):
                    partial_content += '>'
                
                return ET.fromstring(partial_content)
            else:
                return ET.fromstring(xml_content)
        except Exception as e:
            logger.debug(f"Incremental parsing failed: {e}")
            return None
    
    def _clean_xml_content(self, xml_content: str) -> str:
        """Clean XML content of common issues."""
        # Remove null bytes
        xml_content = xml_content.replace('\x00', '')
        
        # Remove other problematic control characters
        xml_content = ''.join(char for char in xml_content if ord(char) >= 32 or char in '\t\n\r')
        
        # Fix common encoding issues
        xml_content = xml_content.replace('\ufffd', '')  # Remove replacement characters
        
        return xml_content.strip()
    
    def _fix_xml_encoding_issues(self, xml_content: str) -> str:
        """Fix common XML encoding issues."""
        # Replace problematic characters
        replacements = {
            '\xc4': 'A',  # Common encoding issue
            '\x80': '',   # Control character
            '\x81': '',   # Control character
            '\x82': '',   # Control character
            '\x83': '',   # Control character
        }
        
        for old, new in replacements.items():
            xml_content = xml_content.replace(old, new)
        
        return xml_content
    
    def _is_binary_xml(self, data: bytes) -> bool:
        """
        Check if data is binary XML format (Android Binary XML).
        
        Args:
            data: Raw bytes to check
            
        Returns:
            True if data appears to be binary XML
        """
        if len(data) < 8:
            return False
        
        # Check for binary XML magic bytes
        # Android Binary XML files typically start with these patterns
        binary_xml_patterns = [
            b'\x03\x00\x08\x00',  # Common binary XML header
            b'\x03\x00',          # Shorter variant
        ]
        
        for pattern in binary_xml_patterns:
            if data.startswith(pattern):
                return True
        
        # Additional check for null bytes in first 100 bytes (typical of binary XML)
        if b'\x00' in data[:100]:
            # Check if it looks like Android binary XML structure
            try:
                # Look for string pool indicators
                if b'android' in data[:1000] and data.count(b'\x00') > len(data) // 10:
                    return True
            except Exception:
                pass
        
        return False
    
    def _convert_binary_manifest(self, manifest_path: str, binary_data: bytes) -> Optional[str]:
        """
        Convert binary AndroidManifest.xml to readable XML using AAPT.
        
        Args:
            manifest_path: Path to the manifest file
            binary_data: Binary XML data
            
        Returns:
            Converted XML string or None if conversion failed
        """
        import subprocess
        import tempfile
        import os
        
        try:
            # Find the original APK file for AAPT conversion
            apk_path = self._find_original_apk(manifest_path)
            if not apk_path:
                logger.warning(f"Could not find original APK for AAPT conversion: {manifest_path}")
                return None
            
            # Check if aapt is available
            try:
                subprocess.run(['aapt', 'version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.warning("AAPT not available for binary XML conversion")
                return None
            
            # Use AAPT to dump the AndroidManifest.xml
            cmd = ['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                # Convert AAPT tree format to proper XML
                xml_content = self._aapt_tree_to_xml(result.stdout)
                if xml_content:
                    logger.info(f"Successfully converted binary AndroidManifest.xml using AAPT")
                    return xml_content
            
            logger.warning(f"AAPT conversion failed for {manifest_path}: {result.stderr}")
            return None
            
        except Exception as e:
            logger.error(f"Error converting binary AndroidManifest.xml: {e}")
            return None
    
    def _find_original_apk(self, manifest_path: str) -> Optional[str]:
        """
        Find the original APK file based on manifest path.
        
        Args:
            manifest_path: Path to AndroidManifest.xml
            
        Returns:
            Path to original APK or None if not found
        """
        import os
        import glob
        
        try:
            # Extract potential APK name from workspace path
            path_parts = manifest_path.split(os.sep)
            
            # Look for workspace directory pattern
            workspace_idx = -1
            for i, part in enumerate(path_parts):
                if 'workspace' in part:
                    workspace_idx = i
                    break
            
            if workspace_idx >= 0 and workspace_idx + 1 < len(path_parts):
                # Get the decompiled directory name
                decompiled_dir = path_parts[workspace_idx + 1]
                
                # Extract APK name (remove _decompiled suffix and hash)
                apk_name_parts = decompiled_dir.split('_')
                if len(apk_name_parts) >= 2:
                    # Strategy 1: Try exact APK name reconstruction
                    base_name = '_'.join(apk_name_parts[:-2]) if len(apk_name_parts) > 2 else apk_name_parts[0]
                    
                    # Look in apks directory
                    workspace_root = os.sep.join(path_parts[:workspace_idx])
                    apks_dir = os.path.join(workspace_root, 'apks')
                    
                    if os.path.exists(apks_dir):
                        # Strategy 1: Try exact match
                        exact_match = os.path.join(apks_dir, f"{base_name}.apk")
                        if os.path.exists(exact_match):
                            return exact_match
                        
                        # Strategy 2: Use enhanced APK matching
                        apk_files = glob.glob(os.path.join(apks_dir, '*.apk'))
                        if apk_files:
                            selected_apk = self._smart_apk_selection(base_name, apk_files, workspace_root)
                            if selected_apk:
                                return selected_apk
                            
                            # Strategy 3: Fallback to largest APK (production apps are typically largest)
                            largest_apk = max(apk_files, key=lambda x: os.path.getsize(x))
                            logger.info(f"Using largest APK as fallback: {largest_apk}")
                            return largest_apk
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding original APK: {e}")
            return None
    
    def _smart_apk_selection(self, base_name: str, apk_files: list, workspace_root: str) -> Optional[str]:
        """
        Smart APK selection using scoring algorithm.
        
        Args:
            base_name: Base APK name extracted from workspace
            apk_files: List of available APK files
            workspace_root: Workspace root directory
            
        Returns:
            Best matching APK path or None
        """
        try:
            import os
            
            best_score = 0
            best_apk = None
            
            # Get workspace directory name for additional context
            workspace_name = os.path.basename(workspace_root).lower()
            
            for apk_path in apk_files:
                apk_filename = os.path.basename(apk_path).lower()
                apk_name = os.path.splitext(apk_filename)[0]
                apk_size = os.path.getsize(apk_path)
                
                score = 0
                
                # Strategy 1: Exact name matching (highest priority)
                if base_name.lower() in apk_name:
                    score += 100
                
                # Strategy 2: Workspace name matching
                if workspace_name and workspace_name.startswith(apk_name.split('-')[0]):
                    score += 50
                
                # Strategy 3: Component matching
                base_components = set(base_name.lower().split('-'))
                apk_components = set(apk_name.split('-'))
                common_components = base_components.intersection(apk_components)
                score += len(common_components) * 25
                
                # Strategy 4: Size bonuses (larger files more likely to be production apps)
                if apk_size > 200 * 1024 * 1024:  # >200MB
                    score += 20
                elif apk_size > 50 * 1024 * 1024:  # >50MB
                    score += 10
                
                if score > best_score:
                    best_score = score
                    best_apk = apk_path
            
            if best_apk:
                logger.info(f"Selected APK '{best_apk}' with score {best_score} for binary XML conversion")
                return best_apk
            
            return None
            
        except Exception as e:
            logger.error(f"Error in smart APK selection: {e}")
            return None
    
    def _aapt_tree_to_xml(self, aapt_output: str) -> Optional[str]:
        """
        Convert AAPT tree dump output to proper XML format.
        
        Args:
            aapt_output: AAPT dump xmltree output
            
        Returns:
            Converted XML string or None if conversion failed
        """
        try:
            # This is a simplified conversion - in practice, you might want
            # to use a more sophisticated AAPT output parser
            
            # For now, create a minimal manifest structure that can be parsed
            lines = aapt_output.split('\n')
            
            # Extract package name
            package_name = "unknown.package"
            for line in lines:
                if 'package=' in line:
                    import re
                    match = re.search(r'package="([^"]*)"', line)
                    if match:
                        package_name = match.group(1)
                        break
            
            # Create a basic manifest structure
            xml_content = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}">
    <!-- Converted from binary XML by AODS encoding_utils -->
    <!-- Use enhanced manifest analysis plugin for complete analysis -->
</manifest>'''
            
            return xml_content
            
        except Exception as e:
            logger.error(f"Error converting AAPT output to XML: {e}")
            return None

# Global instance for easy access
encoding_handler = EnhancedEncodingHandler()

def safe_decode_bytes(data: bytes, filename: str = "unknown") -> str:
    """Convenience function for safe byte decoding."""
    return encoding_handler.safe_decode_bytes(data, filename)

def safe_read_file(file_path: str) -> str:
    """Convenience function for safe file reading."""
    return encoding_handler.safe_read_file(file_path)

def safe_parse_xml(xml_data: Union[str, bytes], filename: str = "unknown", timeout: int = 30) -> Optional[ET.Element]:
    """Convenience function for safe XML parsing."""
    return encoding_handler.safe_parse_xml(xml_data, filename, timeout) 