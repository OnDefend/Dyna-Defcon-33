"""
Enhanced Secret Extractor for AODS Security Analysis
Extracts and analyzes hardcoded secrets from APK files using multi-method binary analysis.

Implements comprehensive secret detection including:
- Binary string extraction (ASCII, UTF-8, Base64)
- System strings command integration
- SQLite database analysis within APKs
- Entropy-based validation
- Credit card number detection with Luhn algorithm
- Organic pattern matching for promotional codes
"""

import re
import logging
import os
import sqlite3
import subprocess
import zipfile
import base64
import signal
import contextlib
import time
import math
import tempfile
import shutil
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass
from collections import defaultdict

@dataclass
class Secret:
    """Enhanced secret representation with validation and context."""
    secret_type: str
    value: str
    location: str
    confidence: float
    severity: str
    entropy: float
    validation_status: str  # "valid", "invalid", "unverified"
    extraction_method: str
    context: str = ""
    line_number: int = 0

@dataclass
class SecretAnalysisResult:
    """Comprehensive secret analysis result."""
    secrets: List[Secret]
    total_strings_analyzed: int
    extraction_methods_used: List[str]
    files_processed: int
    processing_time: float
    statistics: Dict[str, int]

class EnhancedSecretExtractor:
    """
    Enhanced secret extractor with multi-method binary analysis.
    
    Provides comprehensive secret detection including binary analysis,
    entropy validation, and organic pattern matching.
    """
    
    def __init__(self):
        """Initialize the enhanced secret extractor."""
        self.logger = logging.getLogger(__name__)
        self.secret_patterns = self._initialize_secret_patterns()
        self.compiled_patterns = self._compile_patterns()
        self.entropy_threshold = 4.0
        self.min_string_length = 8
        self.max_string_length = 200
        self.stats = defaultdict(int)
        
        # PERFORMANCE FIX: Tighter limits to prevent timeouts
        self.max_file_size_mb = 1  # Reduced from 5MB to 1MB
        self.max_files_per_session = 300  # Reduced from 500 to 300 for faster scans
        self.max_analysis_time = 180  # Reduced from 300s to 3 minutes
        self.max_secrets_per_session = 5000  # Cap result growth to prevent memory exhaustion
        self.per_file_timeout_seconds = 5  # Per-file timeout to prevent single-file hangs
        self.files_processed_count = 0
        self.session_start_time = None
        self.total_secrets_found = 0
        
    
    def _initialize_secret_patterns(self) -> Dict[str, List[str]]:
        """Initialize comprehensive secret detection patterns with edge case coverage."""
        return {
            # API Keys and Tokens - Enhanced with edge cases
            "api_key": [
                # Standard patterns
                r"(?i)(?:api[_-]?key|apikey)[\"'\s]*[:=][\"'\s]*([a-z0-9\-_]{20,100})",
                r"(?i)(?:key|token)[\"'\s]*[:=][\"'\s]*([a-z0-9\-_]{20,100})",
                r"\b[a-zA-Z0-9]{32}\b",  # Generic 32-char strings
                r"\b[a-zA-Z0-9]{40}\b",  # Generic 40-char strings
                # Edge cases: Different quote styles, spacing, case variations
                r"(?i)(?:api[_\-\s]*key|apikey)\s*[:=]\s*['\"`]?([a-zA-Z0-9\-_+/]{16,100})['\"`]?",
                r"(?i)(?:access[_\-\s]*key|accesskey)\s*[:=]\s*['\"`]?([a-zA-Z0-9\-_+/]{16,100})['\"`]?",
                r"(?i)(?:client[_\-\s]*key|clientkey)\s*[:=]\s*['\"`]?([a-zA-Z0-9\-_+/]{16,100})['\"`]?",
                # Edge case: Environment variable style
                r"(?i)(?:API_KEY|ACCESS_KEY|CLIENT_KEY)\s*[:=]\s*['\"`]?([a-zA-Z0-9\-_+/]{16,100})['\"`]?",
                # Edge case: JSON/XML attribute style
                r'(?i)"(?:api_key|apikey|access_key|client_key)"\s*:\s*"([a-zA-Z0-9\-_+/]{16,100})"',
                # Edge case: URL parameter style
                r"(?i)[?&](?:api_key|key|token)=([a-zA-Z0-9\-_+/]{16,100})",
                # Edge case: Base64 encoded API keys
                r"(?i)(?:api[_-]?key|key)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/]{20,}={0,2})",
            ],
            # Cloud Service Keys - Enhanced with all major providers
            "firebase_key": [
                r"AIza[0-9A-Za-z\-_]{35}",
                r"(?i)firebase[_-]?key[\"'\s]*[:=][\"'\s]*([a-z0-9\-_]{20,})",
                # Edge cases: Firebase specific patterns
                r"(?i)firebase[_-]?api[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{35,})",
                r"(?i)google[_-]?services[_-]?api[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{35,})",
                r"(?i)fcm[_-]?server[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_:]{100,})",
                # Edge case: Firebase URLs
                r"https://([a-zA-Z0-9\-_]+)\.firebaseio\.com",
                r"https://([a-zA-Z0-9\-_]+)\.firebaseapp\.com",
            ],
            "aws_access_key": [
                r"AKIA[0-9A-Z]{16}",
                r"(?i)aws[_-]?access[_-]?key[\"'\s]*[:=][\"'\s]*([A-Z0-9]{20})",
                # Edge cases: AWS variations
                r"ASIA[0-9A-Z]{16}",  # Temporary credentials
                r"AROA[0-9A-Z]{16}",  # Role credentials
                r"AIDA[0-9A-Z]{16}",  # IAM user credentials
                r"AGPA[0-9A-Z]{16}",  # Group credentials
                r"AIPA[0-9A-Z]{16}",  # Instance profile credentials
                r"ANPA[0-9A-Z]{16}",  # Managed policy credentials
                r"ANVA[0-9A-Z]{16}",  # Version credentials
                # Edge case: Environment variable style
                r"(?i)AWS_ACCESS_KEY_ID[\"'\s]*[:=][\"'\s]*([A-Z0-9]{20})",
            ],
            "aws_secret_key": [
                r"(?i)aws[_-]?secret[_-]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})",
                r"\b[A-Za-z0-9/+=]{40}\b",  # Generic AWS secret format
                # Edge cases: AWS secret variations
                r"(?i)AWS_SECRET_ACCESS_KEY[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})",
                r"(?i)aws[_-]?secret[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})",
                r"(?i)secret[_-]?access[_-]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})",
            ],
            "google_api_key": [
                r"AIza[0-9A-Za-z\-_]{35}",
                r"(?i)google[_-]?api[_-]?key[\"'\s]*[:=][\"'\s]*([a-z0-9\-_]{20,})",
                # Edge cases: Google service variations
                r"(?i)gcp[_-]?api[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{35,})",
                r"(?i)youtube[_-]?api[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{35,})",
                r"(?i)maps[_-]?api[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{35,})",
                r"(?i)places[_-]?api[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{35,})",
            ],
            # Authentication Tokens - Enhanced with modern token types
            "jwt_token": [
                r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                r"(?i)jwt[_-]?token[\"'\s]*[:=][\"'\s]*([a-z0-9\-_.]{20,})",
                # Edge cases: JWT variations
                r"(?i)bearer[\"'\s]*[:=]?[\"'\s]*eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                r"(?i)authorization[\"'\s]*[:=][\"'\s]*bearer\s+eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                # Edge case: JWT in headers
                r"Authorization:\s*Bearer\s+(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)",
            ],
            "bearer_token": [
                r"(?i)bearer[\"'\s]*[:=]?[\"'\s]*([a-z0-9\-_.]{20,})",
                r"(?i)authorization[\"'\s]*[:=][\"'\s]*bearer\s+([a-z0-9\-_.]{20,})",
                # Edge cases: Bearer token variations
                r"(?i)access[_-]?token[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_.+/]{20,})",
                r"(?i)auth[_-]?token[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_.+/]{20,})",
                r"(?i)session[_-]?token[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_.+/]{20,})",
            ],
            "github_token": [
                r"ghp_[A-Za-z0-9]{36}",
                r"ghs_[A-Za-z0-9]{36}",
                r"gho_[A-Za-z0-9]{36}",
                # Edge cases: GitHub token variations
                r"ghu_[A-Za-z0-9]{36}",  # User tokens
                r"ghr_[A-Za-z0-9]{36}",  # Refresh tokens
                r"github_pat_[A-Za-z0-9_]{82}",  # Personal access tokens (new format)
                r"(?i)github[_-]?token[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9_]{40,})",
            ],
            # Private Keys and Certificates - Enhanced with all formats
            "private_key": [
                r"-----BEGIN (RSA )?PRIVATE KEY-----",
                r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
                r"-----BEGIN EC PRIVATE KEY-----",
                r"-----BEGIN OPENSSH PRIVATE KEY-----",
                # Edge cases: Additional key formats
                r"-----BEGIN DSA PRIVATE KEY-----",
                r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
                r"-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----",
                r"-----BEGIN ECDSA PRIVATE KEY-----",
                r"-----BEGIN ED25519 PRIVATE KEY-----",
                # Edge case: Inline private keys
                r"(?i)private[_-]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/=\n\r]{100,})",
            ],
            "certificate": [
                r"-----BEGIN CERTIFICATE-----",
                r"-----BEGIN X509 CERTIFICATE-----",
                # Edge cases: Additional certificate formats
                r"-----BEGIN TRUSTED CERTIFICATE-----",
                r"-----BEGIN NEW CERTIFICATE REQUEST-----",
                r"-----BEGIN CERTIFICATE REQUEST-----",
                r"-----BEGIN X509 CRL-----",
                r"-----BEGIN PKCS7-----",
            ],
            # Database Connection Strings - Enhanced with all major databases
            "database_url": [
                r"(?i)(mongodb|mysql|postgresql|postgres|sqlite)://[^\s\"'<>]+",
                r"(?i)database[_-]?url[\"'\s]*[:=][\"'\s]*([^\"'\s<>{}()]+)",
                r"(?i)db[_-]?connection[\"'\s]*[:=][\"'\s]*([^\"'\s<>{}()]+)",
                # Edge cases: Additional database types
                r"(?i)(redis|memcached|cassandra|couchdb|influxdb|neo4j)://[^\s\"'<>]+",
                r"(?i)(oracle|mssql|sqlserver|db2|sybase)://[^\s\"'<>]+",
                # Edge case: JDBC URLs
                r"jdbc:(mysql|postgresql|oracle|sqlserver|h2|hsqldb|derby)://[^\s\"'<>]+",
                # Edge case: Connection string parameters
                r"(?i)(?:host|server|hostname)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\.-]+)",
                r"(?i)(?:port|dbport)[\"'\s]*[:=][\"'\s]*([0-9]{1,5})",
                r"(?i)(?:database|dbname|db)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9_-]+)",
            ],
            # Passwords and Secrets - Enhanced with variations
            "password": [
                r"(?i)password[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                r"(?i)passwd[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                r"(?i)pwd[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                # Edge cases: Password variations
                r"(?i)pass[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                r"(?i)user[_-]?password[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                r"(?i)admin[_-]?password[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                r"(?i)root[_-]?password[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                # Edge case: Common weak passwords
                r"\b(?:admin|password|123456|qwerty|letmein|welcome|monkey|dragon)\b",
                # Edge case: Password hashes
                r"\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}",  # bcrypt
                r"\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}",  # MD5 crypt
            ],
            "secret": [
                r"(?i)secret[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                r"(?i)client[_-]?secret[\"'\s]*[:=][\"'\s]*([a-z0-9\-_]{20,})",
                # Edge cases: Secret variations
                r"(?i)app[_-]?secret[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{16,})",
                r"(?i)shared[_-]?secret[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{16,})",
                r"(?i)master[_-]?secret[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{16,})",
                r"(?i)encryption[_-]?secret[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_+/]{16,})",
            ],
            # Credit Card Numbers - Enhanced with all major card types
            "credit_card": [
                r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
                # Edge cases: Additional card types
                r"\b(?:2[2-7][0-9]{14})\b",  # Mastercard new range
                r"\b(?:30[0-5][0-9]{11}|36[0-9]{12}|38[0-9]{12})\b",  # Diners Club
                r"\b(?:35(?:2[89]|[3-8][0-9])[0-9]{12})\b",  # JCB
                r"\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b",  # Discover
                # Edge case: Card numbers with separators
                r"\b(?:4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b",
                r"\b(?:5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b",
            ],
            # Social Security Numbers - Enhanced with variations
            "ssn": [
                r"\b\d{3}-\d{2}-\d{4}\b",
                r"\b\d{9}\b",  # 9-digit sequences
                # Edge cases: SSN variations
                r"\b\d{3}\s\d{2}\s\d{4}\b",  # Space separated
                r"\b\d{3}\.\d{2}\.\d{4}\b",  # Dot separated
                # Edge case: Tax ID numbers
                r"\b\d{2}-\d{7}\b",  # EIN format
            ],
            # Phone Numbers - Enhanced with international formats
            "phone": [
                r"\b\d{3}-\d{3}-\d{4}\b",
                r"\(\d{3}\)\s*\d{3}-\d{4}",
                r"\+1\s*\d{3}\s*\d{3}\s*\d{4}",
                # Edge cases: International phone numbers
                r"\+\d{1,3}\s*\d{3,4}\s*\d{3,4}\s*\d{3,4}",
                r"\b\d{10}\b",  # 10-digit US numbers
                r"\b\d{11}\b",  # 11-digit numbers with country code
                # Edge case: Phone with extensions
                r"\b\d{3}-\d{3}-\d{4}\s*(?:ext|x)\s*\d{1,5}\b",
            ],
            # Email Addresses - Enhanced with false positive filtering
            "email": [
                # Primary email pattern with Android/Java exclusions
                r"(?!.*@android\.)(?!.*Landroid/)(?!.*\.L[A-Z])\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                # Edge cases: Email variations with exclusions
                r"(?!.*@android\.)(?!.*Landroid/)\b[A-Za-z0-9._%+-]+\+[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Plus addressing
                r"(?!.*@android\.)(?!.*Landroid/)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\.[A-Z|a-z]{2,}\b",  # Multiple TLDs
                # Edge case: Obfuscated emails
                r"\b[A-Za-z0-9._%+-]+\s*\[at\]\s*[A-Za-z0-9.-]+\s*\[dot\]\s*[A-Z|a-z]{2,}\b",
                r"(?!.*@android\.)(?!.*Landroid/)\b[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\s*\.\s*[A-Z|a-z]{2,}\b",
            ],
            # IP Addresses - Enhanced with all formats
            "ip_address": [
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
                r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",  # IPv6
                # Edge cases: IPv6 variations
                r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b",  # IPv6 with ::
                r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b",  # IPv6 starting with ::
                r"\b(?:[0-9a-fA-F]{1,4}:){1,6}::[0-9a-fA-F]{1,4}\b",  # IPv6 with :: in middle
                # Edge case: IPv4 with CIDR
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b",
                # Edge case: Private IP ranges
                r"\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.)[0-9]{1,3}|192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3})\b",
            ],
            # Promotional/Promo Codes - Enhanced with mobile app patterns
            "promo_code": [
                r"\b[A-Z]{2,}[a-z]+[A-Z][a-z]+\b",          # Generic: ActivationCode, PromoCode
                r"\b[A-Z][a-z]+[A-Z][a-z]+(?:Code|Key)\b",  # Generic: PromoCode, LicenseKey  
                r"\b[A-Z][a-z]+(iz|is|er)[A-Z][a-z]+\b",    # Generic connector patterns
                r"(?i)(?:promo|coupon|discount)[_-]?code[\"'\s]*[:=][\"'\s]*([a-z0-9\-_]{8,30})",
                r"(?i)(?:code|key|token)[\"'\s]*[:=][\"'\s]*([A-Z][a-z]*[A-Z][a-z]*)",
                r"\b[A-Z]{2,}[a-z]{2,}[A-Z]{2,}[a-z]*\b",  # CamelCase patterns
                # Edge cases: Mobile app specific patterns
                r"\b[A-Z0-9]{6,12}\b",  # Short alphanumeric codes
                r"\b[A-Z]{4,8}[0-9]{2,4}\b",  # Letter-number combinations
                r"\b(?:SAVE|GET|WIN|FREE)[A-Z0-9]{2,8}\b",  # Marketing codes
                # Edge case: CTF/Challenge patterns
                r"\b[FfLlAaGg][1-9_][a-zA-Z0-9_]{3,}\b",  # Flag patterns: F1ag_0n3
                r"\b[0-9]+_[a-zA-Z_]+_[a-zA-Z_]+\b",  # Number underscore: 4_overdone_omelets
                r"\bhunter[0-9]*\b",  # hunter2 pattern
                r"\b[a-zA-Z]+[0-9]+[a-zA-Z]*\b",  # Mixed alphanumeric
            ],
            # URLs and Endpoints - Enhanced with mobile app patterns
            "url": [
                r"https?://[^\s\"'<>(){}]+",
                r"(?i)(?:url|endpoint|api)[_-]?(?:base|root)?[\"'\s]*[:=][\"'\s]*([^\s\"'<>(){}]+)",
                # Edge cases: Mobile app specific URLs
                r"(?i)(?:base[_-]?url|api[_-]?url|server[_-]?url)[\"'\s]*[:=][\"'\s]*([^\s\"'<>(){}]+)",
                r"(?i)(?:host|hostname|server)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\.-]+)",
                # Edge case: Deep links and custom schemes
                r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>(){}]+",
                r"(?i)(?:intent|android-app|ios-app)://[^\s\"'<>(){}]+",
                # Edge case: Firebase and cloud URLs
                r"https://[a-zA-Z0-9\-_]+\.(?:firebaseio|firebaseapp|appspot|googleapis)\.com[^\s\"'<>(){}]*",
                r"https://[a-zA-Z0-9\-_]+\.(?:amazonaws|s3)\.com[^\s\"'<>(){}]*",
            ],
            # Base64 Encoded Data - Enhanced with variations
            "base64": [
                r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
                # Edge cases: Base64 variations
                r"[A-Za-z0-9+/]{16,}={0,2}",  # Shorter base64 strings
                r"[A-Za-z0-9\-_]{16,}={0,2}",  # URL-safe base64
                # Edge case: Base64 in different contexts
                r"(?i)base64[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/=]{16,})",
                r"(?i)encoded[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/=]{16,})",
            ],
            # Hexadecimal Strings - Enhanced with variations
            "hex_string": [
                r"\b[a-fA-F0-9]{32,}\b",  # 32+ character hex strings
                # Edge cases: Hex variations
                r"\b[a-fA-F0-9]{16,31}\b",  # Shorter hex strings
                r"\b0x[a-fA-F0-9]{8,}\b",  # Hex with 0x prefix
                r"\\x[a-fA-F0-9]{2}",  # Hex escape sequences
                # Edge case: Hash patterns
                r"\b[a-fA-F0-9]{40}\b",  # SHA-1 hashes
                r"\b[a-fA-F0-9]{64}\b",  # SHA-256 hashes
                r"\b[a-fA-F0-9]{128}\b",  # SHA-512 hashes
            ],
            # Mobile App Specific Patterns
            "mobile_api_key": [
                # Android/iOS specific API key patterns
                r"(?i)(?:android|ios)[_-]?api[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{20,})",
                r"(?i)(?:gcm|fcm)[_-]?(?:api[_-]?key|sender[_-]?id)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_:]{20,})",
                r"(?i)(?:push|notification)[_-]?(?:api[_-]?key|token)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{20,})",
            ],
            "mobile_certificate": [
                # Mobile certificate patterns
                r"(?i)(?:keystore|p12|pfx)[_-]?(?:password|pass)[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{6,})",
                r"(?i)(?:cert|certificate)[_-]?(?:password|pass)[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{6,})",
                # Android signing certificates
                r"(?i)(?:signing|release)[_-]?(?:keystore|key)[_-]?(?:password|pass)[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{6,})",
            ],
            "oauth_credentials": [
                # OAuth specific patterns
                r"(?i)(?:client[_-]?id|consumer[_-]?key)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_.]{16,})",
                r"(?i)(?:client[_-]?secret|consumer[_-]?secret)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_.]{16,})",
                r"(?i)(?:oauth[_-]?token|access[_-]?token)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_.]{16,})",
                r"(?i)(?:refresh[_-]?token)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_.]{16,})",
            ],
            "third_party_keys": [
                # Third-party service keys
                r"(?i)(?:stripe|paypal|square)[_-]?(?:api[_-]?key|secret)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{16,})",
                r"(?i)(?:twilio|sendgrid|mailgun)[_-]?(?:api[_-]?key|token)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_.]{16,})",
                r"(?i)(?:facebook|twitter|linkedin)[_-]?(?:app[_-]?secret|api[_-]?key)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{16,})",
                # Slack tokens
                r"xox[bpoa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
                # Discord tokens
                r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
            ],
            "encryption_keys": [
                # Encryption key patterns
                r"(?i)(?:aes|des|rsa)[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
                r"(?i)(?:encryption|cipher)[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
                r"(?i)(?:master|root)[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
                # Android Keystore aliases
                r"(?i)(?:keystore[_-]?alias|key[_-]?alias)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{4,})",
            ],
            "biometric_keys": [
                # Biometric and security keys
                r"(?i)(?:biometric|fingerprint|face)[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
                r"(?i)(?:secure[_-]?element|tee)[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
            ],
            "test_credentials": [
                # Test and debug credentials (often overlooked but dangerous)
                r"(?i)(?:test|debug|dev|staging)[_-]?(?:password|secret|key|token)[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{6,})",
                r"(?i)(?:admin|root|user)[_-]?(?:test|debug)[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{6,})",
                # Common test patterns
                r"\b(?:test123|admin123|password123|secret123|debug123)\b",
                r"\b(?:testuser|testpass|debugpass|devpass)\b",
            ],
            "obfuscated_secrets": [
                # Obfuscated or encoded secrets
                r"(?i)(?:rot13|rot47|caesar)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
                r"(?i)(?:xor|cipher)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
                # Reversed strings
                r"(?i)(?:reverse|reversed)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
                # Custom encoding patterns
                r"(?i)(?:custom|encoded|obfuscated)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
            ],
        }
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile all patterns for performance optimization."""
        compiled = {}
        for secret_type, patterns in self.secret_patterns.items():
            compiled[secret_type] = []
            for pattern in patterns:
                try:
                    compiled[secret_type].append(re.compile(pattern, re.MULTILINE))
                except re.error as e:
                    self.logger.warning(f"Failed to compile pattern {pattern}: {e}")
        return compiled
    def _is_framework_file_efficient(self, file_path: str) -> bool:
        """Efficiently detect framework files to skip for performance."""
        framework_patterns = {
            'com/google/android/gms/',
            'com/google/firebase/',
            'androidx/',
            'android/support/',
            'com/facebook/',
            'com/amazon/',
            'kotlin/',
            'kotlinx/',
            'org/apache/',
            'org/json/',
            'okhttp3/',
            'retrofit2/',
            'com/squareup/',
            'io/reactivex/',
            'rx/internal/',
            'dagger/',
            'javax/'
        }
        file_lower = file_path.lower().replace('\\\\', '/')
        return any(pattern in file_lower for pattern in framework_patterns)
    def _should_skip_file_fast(self, file_path: str, file_size: int = 0) -> bool:
        """Fast file filtering for performance optimization."""
        # Skip framework files
        if self._is_framework_file_efficient(file_path):
            return True
        
        # PERFORMANCE FIX: Skip auto-generated monster files that cause hangs
        file_name = os.path.basename(file_path)
        auto_generated_files = {
            'R.java', 'BuildConfig.java', 'GeneratedMessageLite.java',
            'Manifest.java', 'proguard.txt', 'mapping.txt'
        }
        if file_name in auto_generated_files:
            return True
        
        # PERFORMANCE FIX: Skip files with auto-generated patterns in path
        auto_gen_patterns = {
            '/generated/', '/build/', '/.gradle/', '/proguard/',
            '/lint-results', '/jacoco/', '/test-results/'
        }
        file_lower = file_path.lower().replace('\\', '/')
        if any(pattern in file_lower for pattern in auto_gen_patterns):
            return True
        
        # PERFORMANCE FIX: Reduce file size limit from 2MB to 1MB
        if file_size > 1024 * 1024:  # 1MB limit
            return True
        
        # Skip non-analyzable files
        skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.so', '.a', '.o', '.ttf', '.otf'}
        if any(file_path.lower().endswith(ext) for ext in skip_extensions):
            return True
        return False
    @contextlib.contextmanager
    def analysis_timeout(self, seconds: int):
        """PERFORMANCE FIX: Per-file timeout to prevent hangs on large files."""
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Analysis timed out after {seconds} seconds")
        
        if os.name != 'nt':  # Unix-like systems
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            try:
                yield
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
        else:
            # Windows fallback - no signal timeout
            yield

    def extract_secrets_from_content(self, content: str, location: str = "content", method: str = "content_analysis") -> SecretAnalysisResult:
        """
        Extract secrets from content string (not file path).
        Args:
            content: The content to analyze for secrets
            location: Description of where this content came from (e.g., filename)
            method: Analysis method description
        Returns:
            SecretAnalysisResult with found secrets
        """
        import time
        start_time = time.time()
        # self.logger.debug(f"Analyzing {location}")  # Disabled for performance
        try:
            # PERFORMANCE FIX: Apply per-file timeout to prevent hangs
            with self.analysis_timeout(self.per_file_timeout_seconds):
                # Extract secrets from the content
                secrets, strings_analyzed = self._extract_from_content(content, location, method)
                
                # PERFORMANCE FIX: Cap result growth to prevent memory exhaustion
                if self.total_secrets_found >= self.max_secrets_per_session:
                    self.logger.warning(f"Secret limit reached ({self.max_secrets_per_session}), aborting analysis")
                    return SecretAnalysisResult(
                        secrets=[],
                        total_strings_analyzed=strings_analyzed,
                        extraction_methods_used=[method],
                        files_processed=1,
                        processing_time=time.time() - start_time,
                        statistics=dict(self.stats)
                    )
                
                # Validate secrets
                validated_secrets = self._validate_secrets(secrets)
                self.total_secrets_found += len(validated_secrets)
                
                processing_time = time.time() - start_time
                return SecretAnalysisResult(
                    secrets=validated_secrets,
                    total_strings_analyzed=strings_analyzed,
                    extraction_methods_used=[method],
                    files_processed=1,
                    processing_time=processing_time,
                    statistics=dict(self.stats)
                )
        except Exception as e:
            self.logger.error(f"❌ Error during secret extraction: {e}")
            processing_time = time.time() - start_time
            return SecretAnalysisResult(
                secrets=[],
                total_strings_analyzed=0,
                extraction_methods_used=[],
                files_processed=0,
                processing_time=processing_time,
                statistics={}
            )
    def extract_secrets(self, apk_path: str) -> SecretAnalysisResult:
        """
        Extract secrets from APK file using comprehensive multi-method analysis.
        Args:
            apk_path: Path to the APK file
        Returns:
            SecretAnalysisResult with comprehensive analysis
        """
        import time
        start_time = time.time()
        self.logger.info(f"🔍 Starting comprehensive secret extraction for {apk_path}")
        all_secrets = []
        methods_used = []
        files_processed = 0
        strings_analyzed = 0
        try:
            # Method 1: Extract from decompiled directory
            secrets, files, strings = self._extract_from_decompiled(apk_path)
            all_secrets.extend(secrets)
            files_processed += files
            strings_analyzed += strings
            methods_used.append("decompiled_analysis")
            # Method 2: Direct APK analysis (ZIP structure)
            secrets, files, strings = self._extract_from_apk_zip(apk_path)
            all_secrets.extend(secrets)
            files_processed += files
            strings_analyzed += strings
            methods_used.append("apk_zip_analysis")
            # Method 3: Binary string extraction using system 'strings' command
            secrets, strings = self._extract_using_strings_command(apk_path)
            all_secrets.extend(secrets)
            strings_analyzed += strings
            methods_used.append("binary_strings")
            # Method 4: SQLite database analysis
            secrets, files = self._extract_from_sqlite_databases(apk_path)
            all_secrets.extend(secrets)
            files_processed += files
            methods_used.append("sqlite_analysis")
            # Method 5: DEX bytecode analysis
            secrets, strings = self._extract_from_dex_bytecode(apk_path)
            all_secrets.extend(secrets)
            strings_analyzed += strings
            methods_used.append("dex_analysis")
            # Deduplicate and validate secrets
            unique_secrets = self._deduplicate_secrets(all_secrets)
            validated_secrets = self._validate_secrets(unique_secrets)
            processing_time = time.time() - start_time
            self.logger.info(f"✅ Found {len(validated_secrets)} validated secrets using {len(methods_used)} methods")
        except Exception as e:
            self.logger.error(f"❌ Error during secret extraction: {e}")
            validated_secrets = []
            processing_time = time.time() - start_time
        return SecretAnalysisResult(
            secrets=validated_secrets,
            total_strings_analyzed=strings_analyzed,
            extraction_methods_used=methods_used,
            files_processed=files_processed,
            processing_time=processing_time,
            statistics=dict(self.stats)
        )
    def _should_skip_framework_file(self, file_path: str) -> bool:
        """
        Check if file should be skipped as framework/library code.
        Enhanced framework detection to reduce false positives from third-party libraries.
        Args:
            file_path: Path to the file
        Returns:
            True if file should be skipped
        """
        # Comprehensive framework filtering - Enhanced for maximum false positive reduction
        framework_patterns = [
            # Kotlin ecosystem - frequently generates false positives
            'kotlin/',
            'kotlinx/',
            'org/jetbrains/kotlin/',
            # Android framework libraries - comprehensive coverage
            'android/support/',             # Legacy support library
            'androidx/',                    # AndroidX library
            'com/google/android/',          # Google Android libraries
            'com/android/',                 # Core Android packages
            'android/arch/',                # Architecture components
            'android/databinding/',         # Data binding
            'android/content/',             # Content framework
            'android/graphics/',            # Graphics framework
            'android/hardware/',            # Hardware abstraction
            'android/net/',                 # Networking framework
            'android/os/',                  # Operating system
            'android/provider/',            # Content providers
            'android/security/',            # Security framework
            'android/util/',                # Utilities
            'android/view/',                # View system
            'android/widget/',              # UI widgets
            'android/animation/',           # Animation framework
            'android/transition/',          # Transition framework
            # Google libraries - expanded coverage
            'com/google/',                  # All Google packages
            'com/googleapis/',              # Google APIs
            'com/google/protobuf/',         # Protocol buffers
            'com/google/gson/',             # JSON serialization
            'com/google/guava/',            # Google core libraries
            'com/google/common/',           # Google common utilities
            'com/google/firebase/',        # Firebase SDK
            'com/google/ads/',              # Advertising SDK
            'com/google/android/gms/',      # Google Mobile Services
            'com/google/android/play/',     # Google Play Services
            'com/google/api/',              # Google API client
            # Java standard library - comprehensive coverage
            'java/lang/',
            'java/util/',
            'java/io/',
            'java/net/',
            'java/security/',
            'java/text/',
            'java/time/',
            'java/math/',
            'java/nio/',
            'java/concurrent/',
            'java/reflect/',
            'java/beans/',
            'java/awt/',
            'java/applet/',
            'javax/',
            'sun/',                         # Sun internal packages
            'com/sun/',                     # Sun implementation packages
            'jdk/',                         # JDK internal packages
            # JetBrains libraries - expanded
            'org/jetbrains/',
            'org/intellij/',
            'com/intellij/',
            # Apache libraries - comprehensive
            'org/apache/',
            'org/apache/commons/',          # Apache Commons
            'org/apache/http/',             # HTTP components
            'org/apache/log4j/',            # Logging
            'org/apache/cordova/',          # Cordova/PhoneGap
            # OkHttp/OkIO ecosystem - major source of false positives
            'okhttp3/',
            'okio/',                        # Major false positive source
            'com/squareup/okhttp/',
            'com/squareup/okio/',
            'com/squareup/moshi/',
            'com/squareup/retrofit/',
            'com/squareup/picasso/',
            'com/squareup/leakcanary/',
            'com/squareup/javapoet/',
            'com/squareup/wire/',
            'com/squareup/',
            # Network and HTTP libraries
            'retrofit2/',
            'okio/',
            'org/apache/http/',
            'java/net/http/',
            'io/netty/',
            'org/eclipse/jetty/',
            'com/ning/http/',
            # JSON and serialization libraries
            'org/json/',
            'com/fasterxml/',               # Jackson JSON processor
            'com/google/gson/',
            'org/codehaus/jackson/',
            'net/minidev/json/',
            'flexjson/',
            # Reactive programming
            'io/reactivex/',
            'rx/',
            'reactor/',
            'org/reactivestreams/',
            # Dependency injection
            'dagger/',
            'com/google/dagger/',
            'javax/inject/',
            'org/springframework/',
            'com/google/inject/',
            # Logging frameworks
            'org/slf4j/',
            'ch/qos/logback/',
            'org/apache/log4j/',
            'java/util/logging/',
            'timber/',
            'com/jakewharton/timber/',
            # Testing frameworks
            'org/junit/',
            'org/mockito/',
            'org/hamcrest/',
            'org/testng/',
            'org/powermock/',
            'com/nhaarman/',                # Mockito-Kotlin
            'org/robolectric/',
            'androidx/test/',
            'android/support/test/',
            'com/google/truth/',
            'org/assertj/',
            # Popular Android libraries
            'com/airbnb/lottie/',           # Lottie animations
            'com/bumptech/glide/',          # Image loading (Glide)
            'com/jakewharton/',             # Jake Wharton libraries
            'leakcanary/',                  # Memory leak detection
            'butterknife/',                 # View binding (deprecated)
            'eventbus/',                    # Event handling
            'picasso/',                     # Image loading
            'com/facebook/fresco/',         # Image loading (Fresco)
            'com/facebook/stetho/',         # Debug bridge
            'com/facebook/flipper/',        # Debugging platform
            'com/facebook/react/',          # React Native
            # Analytics and crash reporting
            'com/crashlytics/',
            'io/fabric/',
            'com/flurry/',
            'com/mixpanel/',
            'com/amplitude/',
            'com/google/analytics/',
            'com/google/firebase/analytics/',
            'com/bugsnag/',
            'com/rollbar/',
            'io/sentry/',
            # Database and ORM
            'org/hibernate/',
            'org/mybatis/',
            'com/j256/ormlite/',
            'io/realm/',
            'com/raizlabs/android/dbflow/',
            'android/arch/persistence/',
            'androidx/room/',
            'androidx/sqlite/',
            # Build and annotation processing
            'com/google/auto/',
            'org/gradle/',
            'com/android/tools/',
            'com/android/builder/',
            'proguard/',
            'com/guardsquare/proguard/',
            # Security and cryptography frameworks
            'org/bouncycastle/',
            'javax/crypto/',
            'java/security/',
            'org/conscrypt/',
            'com/google/crypto/',
            # Build and test frameworks
            '/R.java',
            '/BuildConfig.java',
            'test/',
            'androidTest/',
            # React Native / JavaScript
            'com/facebook/react/',
            'com/facebook/hermes/',
            # Flutter
            'io/flutter/',
            'dev/flutter/',
            # Networking libraries
            'com/android/volley/',
            'org/apache/http/',
            'java/net/http/',
            # Serialization libraries
            'com/google/gson/',
            'com/fasterxml/jackson/',
            'org/json/',
            # Dependency injection
            'javax/inject/',
            'com/google/inject/',
            # Logging frameworks
            'org/apache/log4j/',
            'ch/qos/logback/',
            'org/slf4j/',
            # Testing frameworks
            'org/robolectric/',
            'com/google/truth/',
            'org/powermock/',
            # UI frameworks
            'com/google/android/material/',
            'androidx/compose/',
            # Database frameworks
            'androidx/room/',
            'org/hibernate/',
            # Additional common patterns
            'META-INF/',
            'assets/flutter_assets/',
            '/generated/',
            '/.gradle/',
        ]
        file_path_lower = file_path.lower()
        # Check exact patterns
        for pattern in framework_patterns:
            if pattern.lower() in file_path_lower:
                return True
        # Enhanced heuristics for framework detection
        # Skip files with very generic class names in framework packages
        generic_names = [
            'util', 'helper', 'builder', 'factory', 'manager', 'handler', 'listener',
            'adapter', 'fragment', 'activity', 'service', 'receiver', 'provider',
            'converter', 'serializer', 'deserializer', 'parser', 'validator',
            'interceptor', 'transformer', 'processor', 'executor', 'scheduler',
            'config', 'constants', 'settings', 'preferences', 'cache'
        ]
        for name in generic_names:
            if f'/{name}.java' in file_path_lower or f'/{name}kt.java' in file_path_lower:
                # Only skip if it's in a framework-like package structure
                if any(fw in file_path_lower for fw in ['com/', 'org/', 'io/', 'androidx/', 'android/']):
                    return True
        # Skip auto-generated files with expanded detection
        generated_indicators = [
            '$', 'Generated', 'Parcelable', 'CREATOR', 'BuildConfig', 'R.java',
            'Manifest', 'databinding', 'BR.java', '_ViewBinding', '_Binding',
            'AutoValue_', 'Dagger', '_Factory', '_MembersInjector', '_Module',
            '_Component', 'ViewHolder', 'LayoutContainer'
        ]
        for indicator in generated_indicators:
            if indicator in file_path:
                self.logger.debug(f"Skipping auto-generated file: {file_path}")
                return True
        # Enhanced framework detection by file structure patterns
        framework_indicators = [
            '/support/constraint/',         # Major false positive source
            '/support/graphics/',           # Major false positive source  
            '/support/design/',
            '/support/v4/',
            '/support/v7/',
            '/support/annotation/',
            '/constraint/solver/',          # Specific false positive source
            '/graphics/drawable/',          # Specific false positive source
            '/internal/',                   # Internal implementation
            '/impl/',                       # Implementation packages
            '/compat/',                     # Compatibility layers
            '/core/internal/',              # Core internal packages
            '/runtime/internal/',           # Runtime internals
        ]
        for indicator in framework_indicators:
            if indicator in file_path_lower:
                self.logger.debug(f"Skipping framework file by structure: {file_path}")
                return True
        return False
    def _is_framework_content(self, content: str, file_path: str) -> bool:
        """
        Enhanced content-aware framework detection to reduce false positives.
        Analyzes actual file content to determine if it's framework code.
        """
        if not content or len(content.strip()) < 50:
            return False
        # Convert to lowercase for case-insensitive analysis
        content_lower = content.lower()
        # Framework package imports analysis
        framework_imports = [
            'import android.support.',
            'import androidx.',
            'import com.google.android.',
            'import java.lang.',
            'import java.util.',
            'import kotlin.',
            'import kotlinx.',
            'import okio.',
            'import okhttp3.',
            'import com.squareup.',
            'import org.apache.',
            'import com.google.',
            'import javax.',
            'import org.jetbrains.',
        ]
        framework_import_count = sum(1 for imp in framework_imports if imp in content_lower)
        # Calculate framework import ratio
        total_imports = content_lower.count('import ')
        framework_ratio = framework_import_count / max(total_imports, 1)
        # High framework import ratio indicates framework code
        if framework_ratio > 0.7:
            self.logger.debug(f"Framework content detected by imports: {file_path} ({framework_ratio:.2f})")
            return True
        # Framework-specific code patterns
        framework_patterns = [
            '@override',
            '@nullable',
            '@nonnull',
            'public static final',
            'private static final',
            'static final class',
            'serialversionuid',
            'generated by',
            'auto-generated',
            'do not edit',
            'build config',
            'manifest',
            'version code',
            'version name',
            'android:',
            'layout_width',
            'layout_height',
            'framework internal',
            'implementation detail',
            'androidx annotation',
            'support library',
        ]
        pattern_matches = sum(1 for pattern in framework_patterns if pattern in content_lower)
        # Check for framework-specific constants and structures
        framework_constants = [
            'match_parent',
            'wrap_content',
            'fill_parent',
            'center_horizontal',
            'center_vertical',
            'invisible',
            'visible',
            'gone',
            'android.r.id',
            'android.r.layout',
            'android.r.string',
            'android.r.drawable',
            'build.version',
            'sdk_int',
        ]
        constant_matches = sum(1 for const in framework_constants if const in content_lower)
        # Enhanced Base64/encoded content detection for framework files
        base64_like_strings = 0
        hex_like_strings = 0
        encoded_content_ratio = 0
        # Look for Base64-like patterns (common in framework files)
        import re
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, content)
        base64_like_strings = len(base64_matches)
        # Look for hex-like patterns
        hex_pattern = r'[0-9A-Fa-f]{16,}'
        hex_matches = re.findall(hex_pattern, content)
        hex_like_strings = len(hex_matches)
        # Calculate encoded content ratio
        total_chars = len(content)
        encoded_chars = sum(len(match) for match in base64_matches + hex_matches)
        if total_chars > 0:
            encoded_content_ratio = encoded_chars / total_chars
        # Framework files often have high encoded content (resources, assets, etc.)
        if encoded_content_ratio > 0.3:
            self.logger.debug(f"High encoded content detected (framework): {file_path} ({encoded_content_ratio:.2f})")
            return True
        # Scoring system for framework content detection
        framework_score = 0
        # Import-based scoring
        framework_score += framework_ratio * 30
        # Pattern-based scoring  
        pattern_ratio = pattern_matches / max(len(content.split('\n')), 1)
        framework_score += pattern_ratio * 20
        # Constants-based scoring
        constant_ratio = constant_matches / max(len(content.split('\n')), 1)
        framework_score += constant_ratio * 15
        # File structure scoring
        if any(indicator in file_path.lower() for indicator in [
            '/internal/', '/impl/', '/compat/', '/generated/', '/build/', '/.gradle/'
        ]):
            framework_score += 10
        # Package structure scoring
        if any(pkg in file_path.lower() for pkg in [
            'android/support/', 'androidx/', 'com/google/', 'org/apache/', 'javax/'
        ]):
            framework_score += 15
        # Decision threshold
        is_framework = framework_score > 25
        if is_framework:
            self.logger.debug(f"Framework content detected by analysis: {file_path} (score: {framework_score:.1f})")
        return is_framework
    def _extract_from_decompiled(self, apk_path: str) -> Tuple[List[Secret], int, int]:
        """Extract secrets from decompiled directory with performance optimization."""
        secrets = []
        files_processed = 0
        strings_analyzed = 0
        # Initialize session tracking
        if self.session_start_time is None:
            self.session_start_time = time.time()
        apk_name = Path(apk_path).stem
        decompiled_dir = Path("workspace") / f"{apk_name}_decompiled"
        if decompiled_dir.exists():
            # Fast file discovery with filtering
            app_files = []
            for file_path in decompiled_dir.rglob("*"):
                if file_path.is_file():
                    # Fast framework filtering
                    if self._should_skip_file_fast(str(file_path), file_path.stat().st_size):
                        continue
                    if self._is_text_file(file_path):
                        app_files.append(file_path)
            # Prioritize important files
            priority_files = self._prioritize_files_for_analysis(app_files)
            # Limit files for performance
            max_files = min(200, len(priority_files))  # Process max 200 files
            files_to_process = priority_files[:max_files]
            self.logger.info(f"Processing {len(files_to_process)} priority files (skipped {len(app_files) - len(files_to_process)} framework/low-priority files)")
            # Batch processing for efficiency
            batch_size = 10
            for i in range(0, len(files_to_process), batch_size):
                batch = files_to_process[i:i + batch_size]
                batch_secrets, batch_files, batch_strings = self._process_file_batch(batch)
                secrets.extend(batch_secrets)
                files_processed += batch_files
                strings_analyzed += batch_strings
                # Check limits
                if time.time() - self.session_start_time > self.max_analysis_time:
                    self.logger.warning(f"Analysis timeout reached, processed {files_processed} files")
                    break
                if files_processed >= self.max_files_per_session:
                    self.logger.warning(f"File limit reached, processed {files_processed} files")
                    break
        return secrets, files_processed, strings_analyzed
    def _prioritize_files_for_analysis(self, files: List[Path]) -> List[Path]:
        """Prioritize files for analysis based on security relevance."""
        high_priority = []
        medium_priority = []
        low_priority = []
        for file_path in files:
            file_str = str(file_path).lower()
            # High priority: config, manifests, specific security files
            if any(pattern in file_str for pattern in ['config', 'manifest', 'secret', 'key', 'token', 'auth', 'login', 'credential']):
                high_priority.append(file_path)
            # Medium priority: source code files
            elif file_path.suffix in {'.java', '.kt', '.js', '.xml'}:
                medium_priority.append(file_path)
            # Low priority: everything else
            else:
                low_priority.append(file_path)
        return high_priority + medium_priority + low_priority
    def _process_file_batch(self, batch: List[Path]) -> Tuple[List[Secret], int, int]:
        """Process a batch of files efficiently."""
        secrets = []
        files_processed = 0
        strings_analyzed = 0
        for i, file_path in enumerate(batch):
                # Show current file being processed
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                # Skip very large content
                if len(content) > 100000:  # 100KB limit per file
                    continue
                file_secrets, file_strings = self._extract_from_content(
                    content, str(file_path), "batch_decompiled"
                )
                secrets.extend(file_secrets)
                strings_analyzed += file_strings
                files_processed += 1
            except Exception as e:
                self.logger.debug(f"Error processing {file_path}: {e}")
        return secrets, files_processed, strings_analyzed
    def _extract_from_apk_zip(self, apk_path: str) -> Tuple[List[Secret], int, int]:
        """Extract secrets directly from APK ZIP structure."""
        secrets = []
        files_processed = 0
        strings_analyzed = 0
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for file_info in apk_zip.infolist():
                    if not file_info.is_dir() and self._is_analyzable_file(file_info.filename):
                        # Skip framework files
                        if self._should_skip_framework_file(file_info.filename):
                            self.logger.debug(f"Skipping framework file in APK: {file_info.filename}")
                            continue
                        try:
                            content = apk_zip.read(file_info.filename).decode('utf-8', errors='ignore')
                            file_secrets, file_strings = self._extract_from_content(
                                content, file_info.filename, "apk_zip"
                            )
                            secrets.extend(file_secrets)
                            strings_analyzed += file_strings
                            files_processed += 1
                        except Exception as e:
                            self.logger.debug(f"Error processing {file_info.filename}: {e}")
        except Exception as e:
            self.logger.warning(f"Error analyzing APK ZIP structure: {e}")
        return secrets, files_processed, strings_analyzed
    def _extract_using_strings_command(self, apk_path: str) -> Tuple[List[Secret], int]:
        """Extract strings using system 'strings' command for binary analysis."""
        secrets = []
        strings_analyzed = 0
        try:
            # Use strings command to extract ASCII and UTF-8 strings
            for encoding in ['ascii', 'utf-8']:
                try:
                    cmd = ['strings', '-e', encoding, '-n', str(self.min_string_length), apk_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        strings_output = result.stdout
                        file_secrets, file_strings = self._extract_from_content(
                            strings_output, apk_path, f"binary_strings_{encoding}"
                        )
                        secrets.extend(file_secrets)
                        strings_analyzed += file_strings
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Strings command timeout for {encoding}")
                except FileNotFoundError:
                    self.logger.debug("System 'strings' command not available")
                    break
        except Exception as e:
            self.logger.warning(f"Error using strings command: {e}")
        return secrets, strings_analyzed
    def _extract_from_sqlite_databases(self, apk_path: str) -> Tuple[List[Secret], int]:
        """Extract secrets from SQLite databases within APK."""
        secrets = []
        files_processed = 0
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for file_info in apk_zip.infolist():
                    if file_info.filename.endswith(('.db', '.sqlite', '.sqlite3')):
                        try:
                            # Extract database to temporary file
                            with tempfile.NamedTemporaryFile(delete=False) as temp_db:
                                temp_db.write(apk_zip.read(file_info.filename))
                                temp_db_path = temp_db.name
                            # Analyze database
                            db_secrets = self._analyze_sqlite_database(temp_db_path, file_info.filename)
                            secrets.extend(db_secrets)
                            files_processed += 1
                            # Clean up
                            os.unlink(temp_db_path)
                        except Exception as e:
                            self.logger.debug(f"Error analyzing database {file_info.filename}: {e}")
        except Exception as e:
            self.logger.warning(f"Error extracting SQLite databases: {e}")
        return secrets, files_processed
    def _analyze_sqlite_database(self, db_path: str, db_name: str) -> List[Secret]:
        """Analyze SQLite database for secrets."""
        secrets = []
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            for table in tables:
                table_name = table[0]
                try:
                    cursor.execute(f"SELECT * FROM {table_name}")
                    rows = cursor.fetchall()
                    for row in rows:
                        for value in row:
                            if isinstance(value, str) and len(value) >= self.min_string_length:
                                file_secrets, _ = self._extract_from_content(
                                    value, f"{db_name}:{table_name}", "sqlite_database"
                                )
                                secrets.extend(file_secrets)
                except Exception as e:
                    self.logger.debug(f"Error querying table {table_name}: {e}")
            conn.close()
        except Exception as e:
            self.logger.debug(f"Error connecting to database {db_path}: {e}")
        return secrets
    def _extract_from_dex_bytecode(self, apk_path: str) -> Tuple[List[Secret], int]:
        """Extract secrets from DEX bytecode using dexdump if available."""
        secrets = []
        strings_analyzed = 0
        try:
            # Try to extract DEX strings using dexdump
            cmd = ['dexdump', '-d', apk_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                dex_output = result.stdout
                file_secrets, file_strings = self._extract_from_content(
                    dex_output, apk_path, "dex_bytecode"
                )
                secrets.extend(file_secrets)
                strings_analyzed += file_strings
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.debug("DEX analysis not available or timed out")
        except Exception as e:
            self.logger.warning(f"Error analyzing DEX bytecode: {e}")
        return secrets, strings_analyzed
    def _extract_from_content(self, content: str, location: str, method: str) -> Tuple[List[Secret], int]:
        """Extract secrets from content using all patterns."""
        secrets = []
        strings_analyzed = 0
        # Split content into lines for context
        lines = content.split('\n')
        for secret_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.finditer(content)
                for match in matches:
                    strings_analyzed += 1
                    value = match.group(1) if match.groups() else match.group(0)
                    # Skip if too short or too long
                    if len(value) < self.min_string_length or len(value) > self.max_string_length:
                        continue
                    # Skip obvious false positives
                    if self._is_false_positive(value):
                        continue
                    # Find line context
                    line_number, context = self._find_line_context(match.start(), content, lines)
                    # Calculate entropy
                    entropy = self._calculate_shannon_entropy(value)
                    # Skip low-entropy strings for certain types
                    if secret_type in ['api_key', 'token', 'secret'] and entropy < self.entropy_threshold:
                        continue
                    secret = Secret(
                        secret_type=secret_type,
                        value=value[:100] + "..." if len(value) > 100 else value,
                        location=location,
                        confidence=self._calculate_confidence(secret_type, value, entropy),
                        severity=self._determine_severity(secret_type),
                        entropy=entropy,
                        validation_status="unverified",
                        extraction_method=method,
                        context=context,
                        line_number=line_number
                    )
                    secrets.append(secret)
        return secrets, strings_analyzed
    def _is_text_file(self, file_path: Path) -> bool:
        """Check if file is a text file suitable for analysis."""
        text_extensions = {'.xml', '.json', '.txt', '.smali', '.java', '.kt', '.js', '.html', '.css', '.properties', '.yml', '.yaml'}
        return file_path.suffix.lower() in text_extensions
    def _is_analyzable_file(self, filename: str) -> bool:
        """Check if file in APK is analyzable."""
        analyzable_extensions = {'.xml', '.json', '.txt', '.properties', '.yml', '.yaml'}
        return any(filename.endswith(ext) for ext in analyzable_extensions)
    def _find_line_context(self, position: int, content: str, lines: List[str]) -> Tuple[int, str]:
        """Find line number and context for a match position."""
        char_count = 0
        for i, line in enumerate(lines):
            if char_count <= position < char_count + len(line):
                return i + 1, line.strip()
            char_count += len(line) + 1  # +1 for newline
        return 0, ""
    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy for string validation."""
        if not data:
            return 0.0
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in data:
            char_counts[char] += 1
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy
    def _is_false_positive(self, value: str) -> bool:
        """Enhanced false positive detection with Android/Java framework exclusions."""
        false_positives = [
            "example", "test", "dummy", "placeholder", "your_", "replace_",
            "TODO", "FIXME", "sample", "default", "null", "undefined",
            "password", "secret", "token", "key", "12345", "admin",
            "user", "guest", "root", "anonymous", "public", "private",
            "localhost", "127.0.0.1", "0.0.0.0", "255.255.255.255"
        ]
        
        # Android/Java framework patterns that are false positives
        android_patterns = [
            "@android.", "landroid/", "androidx.", "com.android.", 
            "@override", "@nullable", "@nonnull", "@deprecated", "@suppresslint",
            "com.actionbarsherlock", "android.support.", "android.view.",
            "android.widget.", "android.content.", "android.graphics.",
            "android.util.", "android.text.", "android.net.", "android.io.",
            "java.lang.", "java.util.", "java.io.", "java.reflect.",
            "menuitemimpl", "actionbarsherlock"
        ]
        
        value_lower = value.lower()
        
        # Check Android/Java framework patterns first
        if any(pattern in value_lower for pattern in android_patterns):
            return True
        
        # For email-like strings, only filter if they are obvious test/example emails
        if '@' in value and '.' in value:
            email_false_positives = [
                "example.com", "test.com", "dummy.com", "placeholder.com",
                "your_email", "replace_email", "sample@", "@example", "@test",
                "TODO@", "FIXME@", "null@", "undefined@"
            ]
            if any(efp in value_lower for efp in email_false_positives):
                return True
        else:
            # For non-email strings, check direct matches
            if any(fp in value_lower for fp in false_positives):
                return True
        # Check for repetitive patterns
        if len(set(value)) <= 3:  # Too few unique characters
            return True
        # Check for sequential patterns
        if self._is_sequential_pattern(value):
            return True
        return False
    def _is_sequential_pattern(self, value: str) -> bool:
        """Check if string contains sequential patterns."""
        # Check for sequences like "123456", "abcdef"
        for i in range(len(value) - 3):
            substring = value[i:i+4]
            if substring.isdigit():
                digits = [int(d) for d in substring]
                if all(digits[j] + 1 == digits[j+1] for j in range(3)):
                    return True
            elif substring.isalpha():
                if all(ord(substring[j]) + 1 == ord(substring[j+1]) for j in range(3)):
                    return True
        return False
    def _calculate_confidence(self, secret_type: str, value: str, entropy: float) -> float:
        """Calculate confidence score for secret detection."""
        base_confidence = 0.5
        # Adjust based on secret type specificity
        type_confidence = {
            "firebase_key": 0.9,
            "aws_access_key": 0.9,
            "aws_secret_key": 0.8,
            "github_token": 0.9,
            "jwt_token": 0.8,
            "private_key": 0.95,
            "credit_card": 0.7,
            "promo_code": 0.6,
            "api_key": 0.6,
            "password": 0.4,
            "email": 0.8,
            "phone": 0.7,
            "url": 0.6,
        }.get(secret_type, base_confidence)
        # Adjust based on entropy
        entropy_bonus = min(0.3, entropy / 8.0)  # Max 0.3 bonus for high entropy
        # Adjust based on length
        length_bonus = min(0.1, len(value) / 200.0)  # Max 0.1 bonus for longer strings
        # Special validation for specific types
        validation_bonus = 0.0
        if secret_type == "credit_card" and self._validate_credit_card(value):
            validation_bonus = 0.3
        elif secret_type == "email" and '@' in value and '.' in value:
            validation_bonus = 0.2
        confidence = type_confidence + entropy_bonus + length_bonus + validation_bonus
        return min(1.0, confidence)
    def _validate_credit_card(self, number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        # Remove any spaces or dashes
        number = re.sub(r'[^0-9]', '', number)
        if len(number) < 13 or len(number) > 19:
            return False
        # Luhn algorithm implementation
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10
        return luhn_checksum(number) == 0
    def _determine_severity(self, secret_type: str) -> str:
        """Determine severity based on secret type."""
        severity_map = {
            "private_key": "CRITICAL",
            "aws_access_key": "CRITICAL",
            "aws_secret_key": "CRITICAL",
            "database_url": "HIGH",
            "jwt_token": "HIGH",
            "api_key": "HIGH",
            "firebase_key": "HIGH",
            "google_api_key": "HIGH",
            "github_token": "HIGH",
            "bearer_token": "HIGH",
            "credit_card": "HIGH",
            "ssn": "HIGH",
            "password": "MEDIUM",
            "secret": "MEDIUM",
            "token": "MEDIUM",
            "promo_code": "MEDIUM",
            "email": "LOW",
            "phone": "LOW",
            "url": "LOW",
            "ip_address": "LOW",
            "base64": "INFO",
            "hex_string": "INFO",
        }
        return severity_map.get(secret_type, "LOW")
    def _deduplicate_secrets(self, secrets: List[Secret]) -> List[Secret]:
        """Remove duplicate secrets based on value and type."""
        seen = set()
        unique_secrets = []
        for secret in secrets:
            # Create signature for deduplication
            signature = f"{secret.secret_type}:{secret.value}:{secret.location}"
            if signature not in seen:
                seen.add(signature)
                unique_secrets.append(secret)
        return unique_secrets
    def _validate_secrets(self, secrets: List[Secret]) -> List[Secret]:
        """Validate and enhance secrets with additional checks."""
        validated = []
        for secret in secrets:
            # Perform type-specific validation
            if secret.secret_type == "credit_card":
                secret.validation_status = "valid" if self._validate_credit_card(secret.value) else "invalid"
            elif secret.secret_type == "email":
                secret.validation_status = "valid" if '@' in secret.value and '.' in secret.value else "invalid"
            elif secret.secret_type == "url":
                secret.validation_status = "valid" if secret.value.startswith(('http://', 'https://')) else "unverified"
            else:
                secret.validation_status = "unverified"
            # Enhanced edge case validation
            secret = self._apply_edge_case_validation(secret)
            # Only include secrets that meet minimum confidence threshold
            if secret.confidence >= 0.3:
                validated.append(secret)
                self.stats[f"validated_{secret.secret_type}"] += 1
        return validated
    def _apply_edge_case_validation(self, secret: Secret) -> Secret:
        """Apply comprehensive edge case validation to enhance secret detection."""
        # Check for encoding obfuscation
        obfuscation_info = self._detect_encoding_obfuscation(secret.value)
        if obfuscation_info["is_obfuscated"]:
            secret.context += f" [Obfuscated: {obfuscation_info['encoding_type']}]"
            if obfuscation_info["decoded_value"]:
                secret.value = obfuscation_info["decoded_value"]
                secret.confidence += obfuscation_info["confidence"] * 0.2
        # Context-based confidence adjustment
        context_boost = self._analyze_context_sensitivity(secret.value, secret.context, secret.location)
        secret.confidence = min(1.0, secret.confidence + context_boost)
        # Multi-encoding detection
        if self._is_multi_encoded(secret.value):
            secret.context += " [Multi-encoded]"
            secret.confidence += 0.15
        # Steganography detection
        if self._detect_steganography_patterns(secret.value):
            secret.context += " [Potential steganography]"
            secret.confidence += 0.1
        # Time-based pattern detection
        if self._is_time_based_secret(secret.value):
            secret.context += " [Time-based]"
            secret.confidence += 0.05
        return secret
    def _detect_encoding_obfuscation(self, value: str) -> Dict[str, Any]:
        """Detect and analyze encoding-based obfuscation."""
        obfuscation_info = {
            "is_obfuscated": False,
            "encoding_type": None,
            "decoded_value": None,
            "confidence": 0.0
        }
        # ROT13/ROT47 detection
        if self._is_rot_encoded(value):
            obfuscation_info["is_obfuscated"] = True
            obfuscation_info["encoding_type"] = "ROT"
            obfuscation_info["decoded_value"] = self._decode_rot(value)
            obfuscation_info["confidence"] = 0.8
        # XOR with common keys
        elif self._is_xor_encoded(value):
            obfuscation_info["is_obfuscated"] = True
            obfuscation_info["encoding_type"] = "XOR"
            obfuscation_info["decoded_value"] = self._decode_xor(value)
            obfuscation_info["confidence"] = 0.7
        # Reversed string
        elif self._is_reversed_string(value):
            obfuscation_info["is_obfuscated"] = True
            obfuscation_info["encoding_type"] = "REVERSED"
            obfuscation_info["decoded_value"] = value[::-1]
            obfuscation_info["confidence"] = 0.6
        return obfuscation_info
    def _is_rot_encoded(self, value: str) -> bool:
        """Check if string might be ROT13/ROT47 encoded."""
        if not value or len(value) < 4:
            return False
        # Try ROT13 decode and check if result is more readable
        try:
            import codecs
            decoded = codecs.decode(value, 'rot13')
            return self._is_more_readable(decoded, value)
        except:
            return False
    def _decode_rot(self, value: str) -> str:
        """Decode ROT13/ROT47 encoded string."""
        try:
            import codecs
            return codecs.decode(value, 'rot13')
        except:
            return value
    def _is_xor_encoded(self, value: str) -> bool:
        """Check if string might be XOR encoded with common keys."""
        common_xor_keys = [0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x20, 0x42, 0xFF]
        for key in common_xor_keys:
            try:
                decoded = ''.join(chr(ord(c) ^ key) for c in value if ord(c) ^ key < 128)
                if len(decoded) == len(value) and self._is_more_readable(decoded, value):
                    return True
            except:
                continue
        return False
    def _decode_xor(self, value: str) -> str:
        """Decode XOR encoded string with common keys."""
        common_xor_keys = [0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x20, 0x42, 0xFF]
        for key in common_xor_keys:
            try:
                decoded = ''.join(chr(ord(c) ^ key) for c in value if ord(c) ^ key < 128)
                if len(decoded) == len(value) and self._is_more_readable(decoded, value):
                    return decoded
            except:
                continue
        return value
    def _is_reversed_string(self, value: str) -> bool:
        """Check if string might be a reversed secret."""
        if len(value) < 8:
            return False
        reversed_val = value[::-1]
        return self._is_more_readable(reversed_val, value)
    def _is_more_readable(self, candidate: str, original: str) -> bool:
        """Check if candidate string is more readable than original."""
        if not candidate or not original:
            return False
        # Count readable characters
        candidate_readable = sum(1 for c in candidate if c.isalnum() or c in ' .-_')
        original_readable = sum(1 for c in original if c.isalnum() or c in ' .-_')
        # Check entropy difference
        candidate_entropy = self._calculate_shannon_entropy(candidate)
        original_entropy = self._calculate_shannon_entropy(original)
        # More readable if higher ratio of readable chars and reasonable entropy
        readable_ratio = candidate_readable / len(candidate) if candidate else 0
        return readable_ratio > 0.8 and candidate_entropy > 2.0 and candidate_entropy < original_entropy
    def _analyze_context_sensitivity(self, value: str, context: str, location: str) -> float:
        """Analyze context to determine if a potential secret is contextually appropriate."""
        confidence_boost = 0.0
        # High-confidence contexts
        high_confidence_contexts = [
            "keystore", "credential", "authentication", "login", "auth",
            "secret", "private", "confidential", "secure", "encrypted",
            "api", "token", "key", "password", "pass", "pwd"
        ]
        # Medium-confidence contexts
        medium_confidence_contexts = [
            "config", "settings", "properties", "environment", "env",
            "database", "db", "connection", "url", "endpoint"
        ]
        # Low-confidence contexts (reduce confidence)
        low_confidence_contexts = [
            "test", "demo", "example", "sample", "placeholder",
            "debug", "development", "dev", "staging", "mock"
        ]
        context_lower = (context or "").lower()
        location_lower = (location or "").lower()
        combined_context = f"{context_lower} {location_lower}"
        # Check high-confidence contexts
        for ctx in high_confidence_contexts:
            if ctx in combined_context:
                confidence_boost += 0.3
                break
        # Check medium-confidence contexts
        for ctx in medium_confidence_contexts:
            if ctx in combined_context:
                confidence_boost += 0.15
                break
        # Check low-confidence contexts (penalty)
        for ctx in low_confidence_contexts:
            if ctx in combined_context:
                confidence_boost -= 0.2
                break
        # File-based context analysis
        if "manifest" in location_lower:
            confidence_boost += 0.1
        elif "gradle" in location_lower or "build" in location_lower:
            confidence_boost -= 0.1
        elif "test" in location_lower:
            confidence_boost -= 0.3
        return max(-0.5, min(0.5, confidence_boost))
    def _is_multi_encoded(self, value: str) -> bool:
        """Detect multi-layer encoding (e.g., Base64 of hex, etc.)."""
        # Check if value is Base64 encoded hex
        try:
            import base64
            decoded = base64.b64decode(value).decode('utf-8')
            if re.match(r'^[a-fA-F0-9]+$', decoded) and len(decoded) >= 16:
                return True
        except:
            pass
        # Check if value is hex encoded Base64
        try:
            if re.match(r'^[a-fA-F0-9]+$', value):
                hex_decoded = bytes.fromhex(value).decode('utf-8')
                if re.match(r'^[A-Za-z0-9+/]+=*$', hex_decoded):
                    return True
        except:
            pass
        return False
    def _detect_steganography_patterns(self, value: str) -> bool:
        """Detect potential steganographic patterns in strings."""
        # Check for unusual character distributions
        char_freq = {}
        for char in value:
            char_freq[char] = char_freq.get(char, 0) + 1
        # Steganography often has very specific character patterns
        if len(char_freq) == 2 and len(value) > 20:  # Binary-like patterns
            return True
        # Check for LSB-style patterns (alternating characters)
        if len(value) > 10:
            alternating_pattern = True
            for i in range(1, min(10, len(value))):
                if value[i] == value[i-1]:
                    alternating_pattern = False
                    break
            if alternating_pattern:
                return True
        return False
    def _is_time_based_secret(self, value: str) -> bool:
        """Detect time-based secrets (TOTP, timestamps, etc.)."""
        # Check for TOTP-like patterns (6-8 digits)
        if re.match(r'^\d{6,8}$', value):
            return True
        # Check for timestamp patterns
        if re.match(r'^\d{10,13}$', value):  # Unix timestamps
            try:
                timestamp = int(value)
                # Check if it's a reasonable timestamp (between 2000 and 2050)
                if 946684800 <= timestamp <= 2524608000:  # 2000-01-01 to 2050-01-01
                    return True
            except:
                pass
        # Check for JWT-style timestamps
        if re.match(r'^\d{10}\.\d+$', value):
            return True
        return False
# Maintain backward compatibility
class SecretExtractor(EnhancedSecretExtractor):
    """Backward compatibility wrapper for existing code."""
    
    def __init__(self):
        super().__init__()
        self.logger.info("Using enhanced secret extractor with backward compatibility")
    
    
    def extract_secrets(self, apk_path: str) -> List[Secret]:
        """Legacy interface that returns just the secrets list."""
        result = super().extract_secrets(apk_path)
        return result.secrets