#!/usr/bin/env python3
"""
CWE (Common Weakness Enumeration) Mapper for AODS

Integrates CWE classification with vulnerability assessment to provide
standardized weakness identification and risk scoring alignment.

References:
- CWE Official Site: https://cwe.mitre.org/
- CWE List: https://cwe.mitre.org/data/definitions/699.html
- OWASP Mobile Top 10 to CWE Mapping: https://owasp.org/www-project-mobile-top-10/

"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

@dataclass
class CWEMapping:
    """CWE vulnerability mapping with risk metadata"""

    cwe_id: str
    name: str
    description: str
    base_score: float  # CVSS v3.1 base score
    category: str  # OWASP MASVS category
    severity: str  # Critical/High/Medium/Low
    references: List[str]
    mitigations: List[str]

class MobileSecurityCWE(Enum):
    """
    Mobile-specific CWE mappings aligned with OWASP MASVS categories
    Based on OWASP Mobile Top 10 2024 and MASVS v2.0
    """

    # M1: Improper Platform Usage (MASVS-PLATFORM)
    CWE_250 = "CWE-250"  # Execution with Unnecessary Privileges
    CWE_276 = "CWE-276"  # Incorrect Default Permissions
    CWE_926 = "CWE-926"  # Improper Export of Android Application Components

    # M2: Insecure Data Storage (MASVS-STORAGE)
    CWE_200 = "CWE-200"  # Exposure of Sensitive Information
    CWE_312 = "CWE-312"  # Cleartext Storage of Sensitive Information
    CWE_313 = "CWE-313"  # Cleartext Storage in a File or on Disk
    CWE_316 = "CWE-316"  # Cleartext Storage of Sensitive Information in Memory
    CWE_922 = "CWE-922"  # Insecure Storage of Sensitive Information

    # M3: Insecure Cryptography (MASVS-CRYPTO)
    CWE_261 = "CWE-261"  # Weak Encoding for Password
    CWE_327 = "CWE-327"  # Use of a Broken or Risky Cryptographic Algorithm
    CWE_329 = "CWE-329"  # Not Using a Random IV with CBC Mode
    CWE_330 = "CWE-330"  # Use of Insufficiently Random Values
    CWE_331 = "CWE-331"  # Insufficient Entropy
    CWE_338 = "CWE-338"  # Use of Cryptographically Weak Pseudo-Random Number Generator

    # M4: Insecure Authentication (MASVS-AUTH)
    CWE_287 = "CWE-287"  # Improper Authentication
    CWE_288 = "CWE-288"  # Authentication Bypass Using an Alternate Path or Channel
    CWE_290 = "CWE-290"  # Authentication Bypass by Spoofing
    CWE_294 = "CWE-294"  # Authentication Bypass by Capture-replay
    CWE_798 = "CWE-798"  # Use of Hard-coded Credentials

    # M5: Insufficient Cryptography (MASVS-CRYPTO)
    CWE_310 = "CWE-310"  # Cryptographic Issues
    CWE_311 = "CWE-311"  # Missing Encryption of Sensitive Data
    CWE_325 = "CWE-325"  # Missing Required Cryptographic Step

    # M6: Insecure Network Communication (MASVS-NETWORK)
    CWE_295 = "CWE-295"  # Improper Certificate Validation
    CWE_296 = "CWE-296"  # Improper Following of a Certificate's Chain of Trust
    CWE_297 = "CWE-297"  # Improper Validation of Certificate with Host Mismatch
    CWE_319 = "CWE-319"  # Cleartext Transmission of Sensitive Information
    CWE_326 = "CWE-326"  # Inadequate Encryption Strength
    CWE_757 = "CWE-757"  # Selection of Less-Secure Algorithm During Negotiation

    # M7: Poor Code Quality (MASVS-CODE)
    CWE_78 = "CWE-78"  # OS Command Injection
    CWE_79 = "CWE-79"  # Cross-site Scripting (XSS)
    CWE_89 = "CWE-89"  # SQL Injection
    CWE_94 = "CWE-94"  # Improper Control of Generation of Code
    CWE_22 = "CWE-22"  # Path Traversal
    CWE_502 = "CWE-502"  # Deserialization of Untrusted Data

    # M8: Data Leakage (MASVS-PRIVACY)
    CWE_532 = "CWE-532"  # Insertion of Sensitive Information into Log File
    CWE_534 = "CWE-534"  # Information Exposure Through Debug Information

    # M9: Reverse Engineering (MASVS-RESILIENCE)
    CWE_656 = "CWE-656"  # Reliance on Security Through Obscurity
    CWE_489 = "CWE-489"  # Active Debug Code

    # M10: Runtime Application Self-Protection (MASVS-RESILIENCE)
    CWE_353 = "CWE-353"  # Missing Support for Integrity Check
    CWE_693 = "CWE-693"  # Protection Mechanism Failure

class CWEMapper:
    """
    Maps AODS vulnerability findings to CWE classifications with risk scoring
    """

    # CWE Database with mobile security focus
    CWE_DATABASE: Dict[str, CWEMapping] = {
        "CWE-89": CWEMapping(
            cwe_id="CWE-89",
            name="SQL Injection",
            description="Improper neutralization of special elements used in an SQL command",
            base_score=9.8,  # Critical
            category="Injection",
            severity="Critical",
            references=[
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://owasp.org/www-community/attacks/SQL_Injection",
            ],
            mitigations=[
                "Use parameterized queries and prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege for database access",
                "Use stored procedures with proper parameter handling",
            ],
        ),
        "CWE-22": CWEMapping(
            cwe_id="CWE-22",
            name="Path Traversal",
            description="Improper limitation of a pathname to a restricted directory",
            base_score=7.5,  # High
            category="Path Traversal",
            severity="High",
            references=[
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://owasp.org/www-community/attacks/Path_Traversal",
            ],
            mitigations=[
                "Implement strict input validation for file paths",
                "Use whitelisting for allowed directories and files",
                "Apply proper file access controls and permissions",
                "Avoid user-controlled file path construction",
            ],
        ),
        "CWE-798": CWEMapping(
            cwe_id="CWE-798",
            name="Use of Hard-coded Credentials",
            description="Software contains hard-coded credentials, such as a password or cryptographic key",
            base_score=9.8,  # Critical
            category="Authentication",
            severity="Critical",
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
            ],
            mitigations=[
                "Remove all hardcoded credentials from source code",
                "Use secure credential management systems",
                "Implement proper key management and rotation",
                "Use environment variables or secure configuration files",
            ],
        ),
        "CWE-926": CWEMapping(
            cwe_id="CWE-926",
            name="Improper Export of Android Application Components",
            description="Android application does not properly restrict which components are accessible to other applications",
            base_score=7.3,  # High
            category="Platform Usage",
            severity="High",
            references=[
                "https://cwe.mitre.org/data/definitions/926.html",
                "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
            ],
            mitigations=[
                "Add proper permission controls to exported components",
                "Remove unnecessary exported components",
                "Implement input validation for intent parameters",
                "Use signature-level permissions for sensitive activities",
            ],
        ),
        "CWE-319": CWEMapping(
            cwe_id="CWE-319",
            name="Cleartext Transmission of Sensitive Information",
            description="Software transmits sensitive or security-critical data in cleartext",
            base_score=8.1,  # High
            category="Network Security",
            severity="High",
            references=[
                "https://cwe.mitre.org/data/definitions/319.html",
                "https://owasp.org/www-project-mobile-top-10/2016-risks/m4-insecure-communication",
            ],
            mitigations=[
                "Implement TLS encryption for all network communications",
                "Use certificate pinning for enhanced security",
                "Validate SSL/TLS certificates properly",
                "Disable cleartext traffic in network security config",
            ],
        ),
        "CWE-312": CWEMapping(
            cwe_id="CWE-312",
            name="Cleartext Storage of Sensitive Information",
            description="Software stores sensitive information in cleartext",
            base_score=7.5,  # High
            category="Data Storage",
            severity="High",
            references=[
                "https://cwe.mitre.org/data/definitions/312.html",
                "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
            ],
            mitigations=[
                "Encrypt sensitive data at rest using strong encryption",
                "Use Android Keystore for cryptographic key management",
                "Implement proper access controls for stored data",
                "Avoid storing sensitive data in shared preferences or databases without encryption",
            ],
        ),
        "CWE-327": CWEMapping(
            cwe_id="CWE-327",
            name="Use of a Broken or Risky Cryptographic Algorithm",
            description="Use of a broken or risky cryptographic algorithm",
            base_score=7.4,  # High
            category="Cryptography",
            severity="High",
            references=[
                "https://cwe.mitre.org/data/definitions/327.html",
                "https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography",
            ],
            mitigations=[
                "Use industry-standard encryption algorithms (AES-256, RSA-2048+)",
                "Avoid deprecated algorithms (DES, MD5, SHA1 for cryptographic purposes)",
                "Implement proper key derivation functions (PBKDF2, scrypt, Argon2)",
                "Regular security reviews of cryptographic implementations",
            ],
        ),
    }

    # Vulnerability pattern to CWE mapping
    PATTERN_TO_CWE: Dict[str, str] = {
        # Injection vulnerabilities
        "sql injection": "CWE-89",
        "injection vulnerabilities": "CWE-89",
        "command injection": "CWE-78",
        "code injection": "CWE-94",
        # Path traversal
        "path traversal": "CWE-22",
        "traversal vulnerabilities": "CWE-22",
        "directory traversal": "CWE-22",
        # Authentication/Credentials
        "hardcoded secret": "CWE-798",
        "hard-coded credentials": "CWE-798",
        "authentication bypass": "CWE-287",
        # Platform-specific
        "attack surface analysis": "CWE-926",
        "exported component": "CWE-926",
        "improper platform usage": "CWE-926",
        # Network security
        "clear-text-traffic": "CWE-319",
        "cleartext traffic": "CWE-319",
        "clear text traffic": "CWE-319",
        "insecure communication": "CWE-319",
        # Data storage
        "insecure data storage": "CWE-312",
        "cleartext storage": "CWE-312",
        # Cryptography
        "insufficient cryptography": "CWE-327",
        "weak cryptography": "CWE-327",
        "broken cryptography": "CWE-327",
        # Information disclosure
        "information disclosure": "CWE-200",
        "sensitive information exposure": "CWE-200",
        "data leakage": "CWE-532",
    }

    def __init__(self):
        """Initialize CWE mapper"""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def map_vulnerability_to_cwe(
        self, title: str, content: str = ""
    ) -> Optional[CWEMapping]:
        """
        Map vulnerability to CWE classification

        Args:
            title: Vulnerability title
            content: Vulnerability description/content

        Returns:
            CWEMapping: Mapped CWE information or None if no match
        """
        title_lower = title.lower()
        content_lower = str(content).lower()
        combined_text = f"{title_lower} {content_lower}"

        # Check direct pattern matches
        for pattern, cwe_id in self.PATTERN_TO_CWE.items():
            if pattern in combined_text:
                cwe_mapping = self.CWE_DATABASE.get(cwe_id)
                if cwe_mapping:
                    self.logger.debug(
                        f"Mapped '{title}' to {cwe_id}: {cwe_mapping.name}"
                    )
                    return cwe_mapping

        self.logger.debug(f"No CWE mapping found for vulnerability: {title}")
        return None

    def get_cwe_by_id(self, cwe_id: str) -> Optional[CWEMapping]:
        """Get CWE mapping by CWE ID"""
        return self.CWE_DATABASE.get(cwe_id)

    def get_all_mobile_cwes(self) -> List[CWEMapping]:
        """Get all mobile security CWE mappings"""
        return list(self.CWE_DATABASE.values())

    def enhance_vulnerability_with_cwe(self, vulnerability: Dict) -> Dict:
        """
        Enhance vulnerability dictionary with CWE information

        Args:
            vulnerability: Vulnerability dictionary from report generator

        Returns:
            Enhanced vulnerability with CWE metadata
        """
        title = vulnerability.get("title", "")
        content = vulnerability.get("description", "")

        cwe_mapping = self.map_vulnerability_to_cwe(title, content)

        if cwe_mapping:
            vulnerability.update(
                {
                    "cwe_id": cwe_mapping.cwe_id,
                    "cwe_name": cwe_mapping.name,
                    "cwe_description": cwe_mapping.description,
                    "cwe_references": cwe_mapping.references,
                    "cwe_mitigations": cwe_mapping.mitigations,
                    "cwe_base_score": cwe_mapping.base_score,
                }
            )

            # Update severity if CWE provides more accurate assessment
            if (
                not vulnerability.get("severity")
                or vulnerability.get("severity") == "Unknown"
            ):
                vulnerability["severity"] = cwe_mapping.severity

        return vulnerability

def get_cwe_url(cwe_id: str) -> str:
    """Get official CWE URL for given CWE ID"""
    cwe_number = cwe_id.replace("CWE-", "")
    return f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"

def get_owasp_mobile_mapping_url() -> str:
    """Get OWASP Mobile Top 10 to CWE mapping reference"""
    return "https://owasp.org/www-project-mobile-top-10/"

def get_masvs_cwe_alignment_url() -> str:
    """Get OWASP MASVS CWE alignment reference"""
    return "https://github.com/OWASP/owasp-masvs/blob/master/Document/0x08-V1-Architecture_design_and_threat_modeling_requireme.md"
