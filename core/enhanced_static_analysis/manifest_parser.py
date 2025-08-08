#!/usr/bin/env python3
"""
Android Manifest Parser

Handles parsing of Android manifest files, including binary XML format.
"""

import logging
import xml.etree.ElementTree as ET
from typing import List, Optional

from rich.console import Console

class AndroidManifestParser:
    """Enhanced AndroidManifest.xml parser with binary XML support."""

    def __init__(self):
        """Initialize the manifest parser."""
        self.console = Console()

    def parse_binary_xml(self, binary_data: bytes) -> Optional[ET.Element]:
        """Parse binary XML AndroidManifest.xml file."""
        try:
            # Try to use aapt or aapt2 for binary XML parsing
            # For now, we'll implement basic binary XML detection and fallback

            # Check if it's binary XML (starts with specific binary XML header)
            if (
                binary_data.startswith(b"\x03\x00\x08\x00")
                or b"androidbinary" in binary_data[:100]
            ):
                logging.info("Detected binary AndroidManifest.xml")

                # Extract string pool and basic structure
                # This is a simplified approach - full implementation would require
                # complete Android binary XML parser

                # For now, extract readable strings from binary data
                extracted_strings = self._extract_strings_from_binary(binary_data)

                # Create a basic XML structure from extracted strings
                return self._reconstruct_xml_from_strings(extracted_strings)

            # Try parsing as regular XML
            try:
                return ET.fromstring(binary_data.decode("utf-8"))
            except ET.ParseError:
                # Try with different encodings
                for encoding in ["utf-8", "latin-1", "cp1252"]:
                    try:
                        return ET.fromstring(binary_data.decode(encoding))
                    except (ET.ParseError, UnicodeDecodeError):
                        continue

        except Exception as e:
            logging.debug(f"Error parsing AndroidManifest.xml: {e}")

        return None

    def _extract_strings_from_binary(self, binary_data: bytes) -> List[str]:
        """Extract readable strings from binary data."""
        strings = []
        current_string = b""

        for byte in binary_data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= 4:
                    try:
                        decoded = current_string.decode("utf-8")
                        strings.append(decoded)
                    except UnicodeDecodeError:
                        # Log the decode error and continue processing
                        logging.debug(f"Failed to decode string as UTF-8: {current_string[:50]}...")
                        continue
                current_string = b""

        return strings

    def _reconstruct_xml_from_strings(self, strings: List[str]) -> Optional[ET.Element]:
        """Reconstruct basic XML structure from extracted strings."""
        try:
            # Create a basic manifest structure
            manifest = ET.Element("manifest")

            # Categorize strings
            permissions = [s for s in strings if s.startswith("android.permission.")]
            activities = [
                s for s in strings if "." in s and not s.startswith("android.")
            ]

            # Add permissions
            for perm in permissions:
                uses_perm = ET.SubElement(manifest, "uses-permission")
                uses_perm.set("android:name", perm)

            # Add basic application structure
            if activities:
                application = ET.SubElement(manifest, "application")
                for activity in activities[:10]:  # Limit to first 10
                    if "/" not in activity and len(activity.split(".")) >= 3:
                        act_elem = ET.SubElement(application, "activity")
                        act_elem.set("android:name", activity)

            return manifest

        except Exception as e:
            logging.debug(f"Error reconstructing XML: {e}")
            return None

# Export the parser
__all__ = ['AndroidManifestParser'] 