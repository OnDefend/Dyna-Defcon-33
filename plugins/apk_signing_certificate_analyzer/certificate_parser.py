"""
APK Signing Certificate Parser

Module for parsing and extracting certificates from APK signatures across
all Android signing schemes (v1-v4).
"""

import logging
import struct
import base64
import zipfile
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID, ExtensionOID

from .data_structures import (
    SigningCertificate, APKSignature, SignatureScheme, CertificateExtension,
    CertificateSecurityLevel, SignatureVerification, CertificateConstants
)

logger = logging.getLogger(__name__)

class CertificateParser:
    """
    Parser for extracting and analyzing certificates from APK signatures.
    
    Supports all Android APK signature schemes:
    - v1 (JAR signing)
    - v2 (APK Signature Scheme)
    - v3 (Key rotation support)
    - v4 (Incremental delivery)
    """
    
    def __init__(self):
        """Initialize the certificate parser."""
        self.certificates = []
        self.signatures = []
        
        logger.debug("Certificate parser initialized")
    
    def parse_certificate_from_x509(self, cert_der: bytes) -> Optional[SigningCertificate]:
        """
        Parse a certificate from DER-encoded X.509 data.
        
        Args:
            cert_der: DER-encoded certificate data
            
        Returns:
            SigningCertificate object or None if parsing fails
        """
        try:
            # Parse X.509 certificate
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Extract basic certificate information
            subject = self._format_distinguished_name(cert.subject)
            issuer = self._format_distinguished_name(cert.issuer)
            serial_number = str(cert.serial_number)
            
            # Extract validity period
            valid_from = cert.not_valid_before_utc
            valid_to = cert.not_valid_after_utc
            
            # Extract public key information
            public_key = cert.public_key()
            key_algorithm, key_size = self._analyze_public_key(public_key)
            
            # Extract signature algorithm
            signature_algorithm = cert.signature_algorithm_oid._name
            
            # Generate fingerprints
            fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
            fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()
            
            # Check if self-signed
            is_self_signed = cert.issuer == cert.subject
            
            # Convert to PEM format
            certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            # Extract extensions
            extensions = self._extract_extensions(cert)
            
            # Extract subject alternative names
            subject_alt_names = self._extract_subject_alt_names(cert)
            
            # Extract key usage
            key_usage = self._extract_key_usage(cert)
            extended_key_usage = self._extract_extended_key_usage(cert)
            
            # Extract public key in PEM format
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Create certificate object
            signing_cert = SigningCertificate(
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                valid_from=valid_from,
                valid_to=valid_to,
                key_algorithm=key_algorithm,
                key_size=key_size,
                signature_algorithm=signature_algorithm,
                fingerprint_sha256=fingerprint_sha256,
                fingerprint_sha1=fingerprint_sha1,
                is_self_signed=is_self_signed,
                certificate_pem=certificate_pem,
                certificate_der=cert_der,
                extensions=extensions,
                public_key_pem=public_key_pem,
                subject_alt_names=subject_alt_names,
                key_usage=key_usage,
                extended_key_usage=extended_key_usage
            )
            
            # Perform initial security assessment
            self._assess_certificate_security(signing_cert)
            
            logger.debug(f"Successfully parsed certificate: {subject}")
            return signing_cert
            
        except Exception as e:
            logger.error(f"Failed to parse certificate: {e}")
            return None
    
    def parse_certificate_from_pem(self, cert_pem: str) -> Optional[SigningCertificate]:
        """
        Parse a certificate from PEM-encoded data.
        
        Args:
            cert_pem: PEM-encoded certificate data
            
        Returns:
            SigningCertificate object or None if parsing fails
        """
        try:
            # Load PEM certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
            
            # Convert to DER and parse
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            return self.parse_certificate_from_x509(cert_der)
            
        except Exception as e:
            logger.error(f"Failed to parse PEM certificate: {e}")
            return None
    
    def extract_v1_jar_certificates(self, apk_path: str) -> List[SigningCertificate]:
        """
        Extract certificates from APK v1 (JAR) signatures.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            List of signing certificates
        """
        certificates = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for signature files in META-INF
                for file_info in apk_zip.filelist:
                    if (file_info.filename.startswith('META-INF/') and 
                        file_info.filename.endswith(('.RSA', '.DSA', '.EC'))):
                        
                        # Extract signature file
                        sig_data = apk_zip.read(file_info.filename)
                        
                        # Parse PKCS#7 signature
                        cert_list = self._extract_certificates_from_pkcs7(sig_data)
                        certificates.extend(cert_list)
            
            logger.info(f"Extracted {len(certificates)} certificates from v1 signatures")
            return certificates
            
        except Exception as e:
            logger.error(f"Failed to extract v1 certificates: {e}")
            return []
    
    def extract_v2_v3_v4_certificates(self, apk_path: str) -> Dict[SignatureScheme, List[SigningCertificate]]:
        """
        Extract certificates from APK v2/v3/v4 signatures.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Dictionary mapping signature schemes to certificate lists
        """
        scheme_certificates = {}
        
        try:
            # Find and parse APK signing block
            signing_block = self._find_apk_signing_block(apk_path)
            if not signing_block:
                logger.warning("No APK signing block found")
                return scheme_certificates
            
            # Extract certificates for each scheme
            for scheme in [SignatureScheme.V2_APK, SignatureScheme.V3_KEY_ROTATION, SignatureScheme.V4_INCREMENTAL]:
                scheme_data = self._extract_scheme_data(signing_block, scheme)
                if scheme_data:
                    certificates = self._extract_certificates_from_scheme_data(scheme_data, scheme)
                    if certificates:
                        scheme_certificates[scheme] = certificates
            
            total_certs = sum(len(certs) for certs in scheme_certificates.values())
            logger.info(f"Extracted {total_certs} certificates from v2/v3/v4 signatures")
            
            return scheme_certificates
            
        except Exception as e:
            logger.error(f"Failed to extract v2/v3/v4 certificates: {e}")
            return {}
    
    def _format_distinguished_name(self, name: x509.Name) -> str:
        """Format a distinguished name for display."""
        try:
            components = []
            for attribute in name:
                oid_name = attribute.oid._name
                value = attribute.value
                components.append(f"{oid_name}={value}")
            return ", ".join(components)
        except Exception:
            return str(name)
    
    def _analyze_public_key(self, public_key) -> Tuple[str, int]:
        """Analyze public key algorithm and size."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
            
            if isinstance(public_key, rsa.RSAPublicKey):
                return "RSA", public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return "EC", public_key.curve.key_size
            elif isinstance(public_key, dsa.DSAPublicKey):
                return "DSA", public_key.key_size
            else:
                return "Unknown", 0
                
        except Exception as e:
            logger.warning(f"Failed to analyze public key: {e}")
            return "Unknown", 0
    
    def _extract_extensions(self, cert: x509.Certificate) -> List[CertificateExtension]:
        """Extract certificate extensions."""
        extensions = []
        
        try:
            for ext in cert.extensions:
                try:
                    oid_str = ext.oid.dotted_string
                    critical = ext.critical
                    value = str(ext.value)
                    description = self._get_extension_description(ext.oid)
                    
                    cert_ext = CertificateExtension(
                        oid=oid_str,
                        critical=critical,
                        value=value,
                        description=description
                    )
                    extensions.append(cert_ext)
                    
                except Exception as e:
                    logger.warning(f"Failed to parse extension {ext.oid}: {e}")
                    
        except Exception as e:
            logger.warning(f"Failed to extract extensions: {e}")
        
        return extensions
    
    def _extract_subject_alt_names(self, cert: x509.Certificate) -> List[str]:
        """Extract subject alternative names."""
        alt_names = []
        
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in ext.value:
                alt_names.append(str(name))
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.warning(f"Failed to extract subject alt names: {e}")
        
        return alt_names
    
    def _extract_key_usage(self, cert: x509.Certificate) -> List[str]:
        """Extract key usage information."""
        usage_list = []
        
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            key_usage = ext.value
            
            usage_attributes = [
                ('digital_signature', 'Digital Signature'),
                ('content_commitment', 'Content Commitment'),
                ('key_encipherment', 'Key Encipherment'),
                ('data_encipherment', 'Data Encipherment'),
                ('key_agreement', 'Key Agreement'),
                ('key_cert_sign', 'Certificate Signing'),
                ('crl_sign', 'CRL Signing'),
                ('encipher_only', 'Encipher Only'),
                ('decipher_only', 'Decipher Only')
            ]
            
            for attr_name, display_name in usage_attributes:
                if hasattr(key_usage, attr_name) and getattr(key_usage, attr_name):
                    usage_list.append(display_name)
                    
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.warning(f"Failed to extract key usage: {e}")
        
        return usage_list
    
    def _extract_extended_key_usage(self, cert: x509.Certificate) -> List[str]:
        """Extract extended key usage information."""
        usage_list = []
        
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            for usage in ext.value:
                usage_list.append(usage._name)
                
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.warning(f"Failed to extract extended key usage: {e}")
        
        return usage_list
    
    def _get_extension_description(self, oid: x509.ObjectIdentifier) -> str:
        """Get human-readable description for certificate extension OID."""
        descriptions = {
            ExtensionOID.SUBJECT_KEY_IDENTIFIER: "Subject Key Identifier",
            ExtensionOID.KEY_USAGE: "Key Usage",
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "Subject Alternative Name",
            ExtensionOID.ISSUER_ALTERNATIVE_NAME: "Issuer Alternative Name",
            ExtensionOID.BASIC_CONSTRAINTS: "Basic Constraints",
            ExtensionOID.CRL_DISTRIBUTION_POINTS: "CRL Distribution Points",
            ExtensionOID.CERTIFICATE_POLICIES: "Certificate Policies",
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "Authority Key Identifier",
            ExtensionOID.EXTENDED_KEY_USAGE: "Extended Key Usage",
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "Authority Information Access",
            ExtensionOID.SUBJECT_INFORMATION_ACCESS: "Subject Information Access"
        }
        
        return descriptions.get(oid, f"Unknown Extension ({oid.dotted_string})")
    
    def _assess_certificate_security(self, cert: SigningCertificate) -> None:
        """Perform initial security assessment of certificate."""
        issues = []
        security_level = CertificateSecurityLevel.INFO
        
        # Check if certificate is expired
        if cert.is_expired():
            issues.append("Certificate is expired")
            security_level = CertificateSecurityLevel.CRITICAL
        
        # Check key size
        if cert.key_algorithm == "RSA" and cert.key_size < CertificateConstants.MIN_RSA_KEY_SIZE:
            issues.append(f"RSA key size {cert.key_size} is below minimum {CertificateConstants.MIN_RSA_KEY_SIZE}")
            security_level = max(security_level, CertificateSecurityLevel.HIGH)
        elif cert.key_algorithm == "EC" and cert.key_size < CertificateConstants.MIN_EC_KEY_SIZE:
            issues.append(f"EC key size {cert.key_size} is below minimum {CertificateConstants.MIN_EC_KEY_SIZE}")
            security_level = max(security_level, CertificateSecurityLevel.HIGH)
        
        # Check signature algorithm
        if any(weak_algo in cert.signature_algorithm.upper() for weak_algo in CertificateConstants.DEPRECATED_HASH_ALGORITHMS):
            issues.append(f"Weak signature algorithm: {cert.signature_algorithm}")
            security_level = max(security_level, CertificateSecurityLevel.HIGH)
        
        # Check certificate validity period
        # Ensure both dates are timezone-aware for comparison
        from datetime import timezone
        valid_from = cert.valid_from.replace(tzinfo=timezone.utc) if cert.valid_from.tzinfo is None else cert.valid_from
        valid_to = cert.valid_to.replace(tzinfo=timezone.utc) if cert.valid_to.tzinfo is None else cert.valid_to
        validity_period = (valid_to - valid_from).days
        if validity_period > (CertificateConstants.MAX_CERTIFICATE_VALIDITY_YEARS * 365):
            issues.append(f"Certificate validity period ({validity_period} days) is too long")
            security_level = max(security_level, CertificateSecurityLevel.MEDIUM)
        
        # Check for self-signed certificate
        if cert.is_self_signed:
            issues.append("Certificate is self-signed")
            security_level = max(security_level, CertificateSecurityLevel.MEDIUM)
        
        cert.security_issues = issues
        cert.security_level = security_level
    
    def _extract_certificates_from_pkcs7(self, pkcs7_data: bytes) -> List[SigningCertificate]:
        """Extract certificates from PKCS#7 signature data."""
        certificates = []
        
        try:
            # Parse PKCS#7 data and extract certificates
            logger.debug("Parsing PKCS#7 signature data")
            
            # Import PKCS#7 parsing from cryptography
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import pkcs7
            
            try:
                # Load PKCS#7 data - try DER format first
                try:
                    pkcs7_obj = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
                except ValueError:
                    # Try PEM format if DER fails
                    pkcs7_obj = pkcs7.load_pem_pkcs7_certificates(pkcs7_data)
                
                logger.debug(f"Successfully loaded PKCS#7 data with {len(pkcs7_obj)} certificates")
                
                # Extract each certificate
                for cert in pkcs7_obj:
                    try:
                        # Convert certificate to DER format for processing
                        cert_der = cert.public_bytes(serialization.Encoding.DER)
                        
                        # Parse certificate using existing method
                        signing_cert = self.parse_certificate_from_x509(cert_der)
                        if signing_cert:
                            certificates.append(signing_cert)
                            logger.debug(f"Successfully extracted certificate: {signing_cert.subject}")
                        
                    except Exception as cert_e:
                        logger.warning(f"Failed to process individual certificate: {cert_e}")
                        continue
                        
            except Exception as pkcs7_e:
                # Fallback: try to parse as raw certificate data
                logger.debug(f"PKCS#7 parsing failed, trying direct certificate parsing: {pkcs7_e}")
                
                # Sometimes the data might be a direct certificate rather than PKCS#7
                try:
                    signing_cert = self.parse_certificate_from_x509(pkcs7_data)
                    if signing_cert:
                        certificates.append(signing_cert)
                        logger.debug("Successfully parsed as direct certificate")
                except Exception as direct_e:
                    logger.debug(f"Direct certificate parsing also failed: {direct_e}")
                    
                    # Final fallback: try to extract certificates from ASN.1 structure manually
                    certificates.extend(self._extract_certificates_from_asn1(pkcs7_data))
            
            logger.info(f"Extracted {len(certificates)} certificates from PKCS#7 data")
            
        except Exception as e:
            logger.error(f"Failed to extract certificates from PKCS#7: {e}")
        
        return certificates
    
    def _extract_certificates_from_asn1(self, asn1_data: bytes) -> List[SigningCertificate]:
        """Fallback method to extract certificates from ASN.1 data."""
        certificates = []
        
        try:
            from cryptography.hazmat.primitives import serialization
            
            # Try to find certificate patterns in the data
            # Look for DER certificate headers (0x30 0x82 for SEQUENCE)
            offset = 0
            while offset < len(asn1_data) - 4:
                # Look for certificate start pattern
                if (asn1_data[offset] == 0x30 and 
                    asn1_data[offset + 1] == 0x82):
                    
                    # Extract length
                    cert_len = (asn1_data[offset + 2] << 8) | asn1_data[offset + 3]
                    total_len = cert_len + 4
                    
                    if offset + total_len <= len(asn1_data):
                        try:
                            cert_data = asn1_data[offset:offset + total_len]
                            signing_cert = self.parse_certificate_from_x509(cert_data)
                            if signing_cert:
                                certificates.append(signing_cert)
                                logger.debug("Extracted certificate from ASN.1 data")
                        except Exception:
                            pass  # Continue searching
                    
                    offset += total_len
                else:
                    offset += 1
            
        except Exception as e:
            logger.warning(f"ASN.1 certificate extraction failed: {e}")
        
        return certificates
    
    def _find_apk_signing_block(self, apk_path: str) -> Optional[bytes]:
        """Find and extract APK signing block from APK file."""
        try:
            with open(apk_path, 'rb') as f:
                # Find end of central directory
                file_size = f.seek(0, 2)
                eocd_offset = self._find_eocd(f, file_size)
                
                if eocd_offset is None:
                    return None
                
                # Read central directory offset from EOCD
                f.seek(eocd_offset + 16)
                cd_offset = struct.unpack('<I', f.read(4))[0]
                
                # APK signing block should be just before central directory
                f.seek(cd_offset - 24)  # APK signing block footer
                footer = f.read(24)
                
                if footer[-16:] != b'APK Sig Block 42':
                    return None
                
                # Read block size
                block_size = struct.unpack('<Q', footer[:8])[0]
                
                # Read the entire signing block
                f.seek(cd_offset - block_size)
                signing_block = f.read(block_size)
                
                return signing_block
                
        except Exception as e:
            logger.error(f"Failed to find APK signing block: {e}")
            return None
    
    def _find_eocd(self, f, file_size: int) -> Optional[int]:
        """Find End of Central Directory record."""
        # Look for EOCD signature in last 65KB of file
        search_size = min(65536, file_size)
        f.seek(file_size - search_size)
        data = f.read(search_size)
        
        # Search for EOCD signature backwards
        eocd_signature = b'\x50\x4b\x05\x06'
        for i in range(len(data) - 4, -1, -1):
            if data[i:i+4] == eocd_signature:
                return file_size - search_size + i
        
        return None
    
    def _extract_scheme_data(self, signing_block: bytes, scheme: SignatureScheme) -> Optional[bytes]:
        """Extract signature scheme data from APK signing block."""
        scheme_ids = {
            SignatureScheme.V2_APK: CertificateConstants.APK_SIGNATURE_SCHEME_V2_ID,
            SignatureScheme.V3_KEY_ROTATION: CertificateConstants.APK_SIGNATURE_SCHEME_V3_ID,
            SignatureScheme.V4_INCREMENTAL: CertificateConstants.APK_SIGNATURE_SCHEME_V4_ID
        }
        
        target_id = scheme_ids.get(scheme)
        if not target_id:
            return None
        
        try:
            # Parse signing block for scheme data
            offset = 8  # Skip block size
            
            while offset < len(signing_block) - 24:  # Leave space for footer
                # Read pair length
                if offset + 8 > len(signing_block):
                    break
                
                pair_len = struct.unpack('<Q', signing_block[offset:offset+8])[0]
                offset += 8
                
                if offset + pair_len > len(signing_block):
                    break
                
                # Read scheme ID
                scheme_id = struct.unpack('<I', signing_block[offset:offset+4])[0]
                
                if scheme_id == target_id:
                    # Found target scheme data
                    return signing_block[offset+4:offset+pair_len]
                
                offset += pair_len
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract {scheme.value} data: {e}")
            return None
    
    def _extract_certificates_from_scheme_data(self, scheme_data: bytes, scheme: SignatureScheme) -> List[SigningCertificate]:
        """Extract certificates from scheme-specific signature data."""
        certificates = []
        
        try:
            # Parse scheme data structure
            logger.debug(f"Extracting certificates from {scheme.value} data")
            
            # Android APK signature schemes use a specific binary format
            # Each scheme has signers, and each signer has certificates
            offset = 0
            
            if len(scheme_data) < 4:
                logger.warning("Scheme data too short")
                return certificates
            
            # Parse the scheme data based on Android APK signature format
            if scheme in [SignatureScheme.V2_APK, SignatureScheme.V3_KEY_ROTATION]:
                certificates = self._parse_v2_v3_scheme_data(scheme_data, scheme)
            elif scheme == SignatureScheme.V4_INCREMENTAL:
                certificates = self._parse_v4_scheme_data(scheme_data)
            else:
                logger.warning(f"Unsupported scheme for parsing: {scheme.value}")
            
            logger.info(f"Extracted {len(certificates)} certificates from {scheme.value} data")
            
        except Exception as e:
            logger.error(f"Failed to extract certificates from {scheme.value} data: {e}")
        
        return certificates
    
    def _parse_v2_v3_scheme_data(self, scheme_data: bytes, scheme: SignatureScheme) -> List[SigningCertificate]:
        """Parse v2/v3 scheme data to extract certificates."""
        certificates = []
        
        try:
            offset = 0
            
            # Read signers length
            if offset + 4 > len(scheme_data):
                return certificates
            
            signers_len = struct.unpack('<I', scheme_data[offset:offset+4])[0]
            offset += 4
            
            logger.debug(f"Signers length: {signers_len}")
            
            if offset + signers_len > len(scheme_data):
                logger.warning("Invalid signers length")
                return certificates
            
            signers_data = scheme_data[offset:offset+signers_len]
            offset += signers_len
            
            # Parse each signer
            signer_offset = 0
            signer_count = 0
            
            while signer_offset < len(signers_data):
                # Read signer length
                if signer_offset + 4 > len(signers_data):
                    break
                
                signer_len = struct.unpack('<I', signers_data[signer_offset:signer_offset+4])[0]
                signer_offset += 4
                
                if signer_offset + signer_len > len(signers_data):
                    logger.warning(f"Invalid signer {signer_count} length")
                    break
                
                signer_data = signers_data[signer_offset:signer_offset+signer_len]
                signer_offset += signer_len
                signer_count += 1
                
                logger.debug(f"Processing signer {signer_count}, length: {signer_len}")
                
                # Extract certificates from this signer
                signer_certs = self._extract_certificates_from_signer(signer_data, scheme)
                certificates.extend(signer_certs)
                
                logger.debug(f"Extracted {len(signer_certs)} certificates from signer {signer_count}")
            
            logger.debug(f"Processed {signer_count} signers, total certificates: {len(certificates)}")
            
        except Exception as e:
            logger.error(f"Failed to parse v2/v3 scheme data: {e}")
        
        return certificates
    
    def _extract_certificates_from_signer(self, signer_data: bytes, scheme: SignatureScheme) -> List[SigningCertificate]:
        """Extract certificates from a single signer's data."""
        certificates = []
        
        try:
            offset = 0
            
            # Skip signed data length and signed data (signatures)
            if offset + 4 > len(signer_data):
                return certificates
            
            signed_data_len = struct.unpack('<I', signer_data[offset:offset+4])[0]
            offset += 4 + signed_data_len
            
            # Skip signatures length and signatures
            if offset + 4 > len(signer_data):
                return certificates
            
            signatures_len = struct.unpack('<I', signer_data[offset:offset+4])[0]
            offset += 4 + signatures_len
            
            # Read public key (certificate) length
            if offset + 4 > len(signer_data):
                return certificates
            
            public_key_len = struct.unpack('<I', signer_data[offset:offset+4])[0]
            offset += 4
            
            if offset + public_key_len > len(signer_data):
                logger.warning("Invalid public key length")
                return certificates
            
            # Extract the public key data (which contains certificates)
            public_key_data = signer_data[offset:offset+public_key_len]
            
            logger.debug(f"Extracting certificates from public key data, length: {public_key_len}")
            
            # Parse certificates from public key data
            certs = self._parse_certificates_from_public_key_data(public_key_data)
            certificates.extend(certs)
            
            # For v3, there might be additional certificate lineage data
            if scheme == SignatureScheme.V3_KEY_ROTATION:
                offset += public_key_len
                # Try to extract lineage certificates if present
                lineage_certs = self._extract_v3_lineage_certificates(signer_data[offset:])
                certificates.extend(lineage_certs)
            
        except Exception as e:
            logger.error(f"Failed to extract certificates from signer: {e}")
        
        return certificates
    
    def _parse_certificates_from_public_key_data(self, public_key_data: bytes) -> List[SigningCertificate]:
        """Parse certificates from public key data section."""
        certificates = []
        
        try:
            offset = 0
            
            # The public key data typically contains a sequence of certificates
            # Each certificate is prefixed with its length
            while offset < len(public_key_data):
                # Read certificate length
                if offset + 4 > len(public_key_data):
                    break
                
                cert_len = struct.unpack('<I', public_key_data[offset:offset+4])[0]
                offset += 4
                
                if offset + cert_len > len(public_key_data):
                    logger.warning("Invalid certificate length in public key data")
                    break
                
                # Extract certificate data
                cert_data = public_key_data[offset:offset+cert_len]
                offset += cert_len
                
                # Parse the certificate
                try:
                    signing_cert = self.parse_certificate_from_x509(cert_data)
                    if signing_cert:
                        certificates.append(signing_cert)
                        logger.debug(f"Extracted certificate: {signing_cert.subject}")
                except Exception as cert_e:
                    logger.warning(f"Failed to parse individual certificate: {cert_e}")
                    # Try parsing as raw DER data
                    try:
                        # Sometimes the data might need different parsing
                        signing_cert = self._parse_raw_certificate_data(cert_data)
                        if signing_cert:
                            certificates.append(signing_cert)
                    except Exception:
                        logger.debug("Raw certificate parsing also failed")
                        continue
            
        except Exception as e:
            logger.error(f"Failed to parse certificates from public key data: {e}")
        
        return certificates
    
    def _parse_raw_certificate_data(self, cert_data: bytes) -> Optional[SigningCertificate]:
        """Parse raw certificate data with multiple format attempts."""
        try:
            # Try different parsing approaches
            
            # Attempt 1: Direct X.509 parsing
            try:
                return self.parse_certificate_from_x509(cert_data)
            except Exception:
                pass
            
            # Attempt 2: Look for embedded certificate within the data
            # Look for DER certificate pattern (30 82 ...)
            for i in range(len(cert_data) - 4):
                if (cert_data[i] == 0x30 and cert_data[i + 1] == 0x82):
                    # Found potential certificate start
                    try:
                        remaining_data = cert_data[i:]
                        if len(remaining_data) >= 4:
                            # Extract length
                            cert_len = (remaining_data[2] << 8) | remaining_data[3]
                            total_len = cert_len + 4
                            
                            if total_len <= len(remaining_data):
                                candidate_cert = remaining_data[:total_len]
                                signing_cert = self.parse_certificate_from_x509(candidate_cert)
                                if signing_cert:
                                    return signing_cert
                    except Exception:
                        continue
            
            # Attempt 3: Try as PEM if it looks like text
            try:
                if cert_data.startswith(b'-----BEGIN'):
                    pem_str = cert_data.decode('utf-8')
                    return self.parse_certificate_from_pem(pem_str)
            except Exception:
                pass
            
        except Exception as e:
            logger.debug(f"Raw certificate parsing failed: {e}")
        
        return None
    
    def _extract_v3_lineage_certificates(self, lineage_data: bytes) -> List[SigningCertificate]:
        """Extract certificates from v3 key rotation lineage data."""
        certificates = []
        
        try:
            if len(lineage_data) < 4:
                return certificates
            
            # Parse lineage data structure
            offset = 0
            
            # Read lineage length
            lineage_len = struct.unpack('<I', lineage_data[offset:offset+4])[0]
            offset += 4
            
            if offset + lineage_len > len(lineage_data):
                return certificates
            
            lineage_content = lineage_data[offset:offset+lineage_len]
            
            # Parse lineage certificates
            # Lineage contains a chain of certificates showing key rotation
            lineage_offset = 0
            
            while lineage_offset < len(lineage_content):
                # Read certificate entry length
                if lineage_offset + 4 > len(lineage_content):
                    break
                
                entry_len = struct.unpack('<I', lineage_content[lineage_offset:lineage_offset+4])[0]
                lineage_offset += 4
                
                if lineage_offset + entry_len > len(lineage_content):
                    break
                
                entry_data = lineage_content[lineage_offset:lineage_offset+entry_len]
                lineage_offset += entry_len
                
                # Extract certificate from lineage entry
                entry_certs = self._parse_lineage_entry(entry_data)
                certificates.extend(entry_certs)
            
            logger.debug(f"Extracted {len(certificates)} certificates from v3 lineage")
            
        except Exception as e:
            logger.error(f"Failed to extract v3 lineage certificates: {e}")
        
        return certificates
    
    def _parse_lineage_entry(self, entry_data: bytes) -> List[SigningCertificate]:
        """Parse a single lineage entry to extract certificates."""
        certificates = []
        
        try:
            # Lineage entry typically contains certificate data
            # Try to find and extract certificates
            certificates.extend(self._parse_certificates_from_public_key_data(entry_data))
            
        except Exception as e:
            logger.debug(f"Failed to parse lineage entry: {e}")
        
        return certificates
    
    def _parse_v4_scheme_data(self, scheme_data: bytes) -> List[SigningCertificate]:
        """Parse v4 scheme data to extract certificates."""
        certificates = []
        
        try:
            # V4 signature scheme structure is similar to v2/v3 but optimized for incremental delivery
            # For now, use similar parsing logic as v2/v3
            logger.debug("Parsing v4 scheme data using v2/v3 compatible approach")
            
            certificates = self._parse_v2_v3_scheme_data(scheme_data, SignatureScheme.V4_INCREMENTAL)
            
            logger.debug(f"Extracted {len(certificates)} certificates from v4 scheme data")
            
        except Exception as e:
            logger.error(f"Failed to parse v4 scheme data: {e}")
        
        return certificates 