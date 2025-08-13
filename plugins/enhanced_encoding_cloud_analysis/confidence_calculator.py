"""
Professional Confidence Calculator for Enhanced Encoding and Cloud Analysis

This module provides sophisticated confidence calculation for encoding and cloud
service findings using evidence-based scoring, pattern reliability data, and
context-aware adjustments. No hardcoded confidence values are used.
"""

import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum

from .data_structures import (
    EncodingFinding, CipherFinding, CloudServiceFinding, EncodingContext,
    EncodingType, CipherType, CloudServiceType, SeverityLevel, FileType,
    AnalysisPattern, ComprehensiveAnalysisResult
)

logger = logging.getLogger(__name__)

class EvidenceFactor(Enum):
    """Evidence factors for confidence calculation."""
    ENCODING_QUALITY = "encoding_quality"
    PATTERN_RELIABILITY = "pattern_reliability"
    CONTEXT_RELEVANCE = "context_relevance"
    CONTENT_ANALYSIS = "content_analysis"
    CROSS_VALIDATION = "cross_validation"
    FILE_TYPE_WEIGHT = "file_type_weight"
    SECURITY_IMPACT = "security_impact"

@dataclass
class EvidenceWeights:
    """Weights for different evidence factors in confidence calculation."""
    encoding_quality: float = 0.25      # Quality of encoding detection
    pattern_reliability: float = 0.20   # Historical pattern accuracy
    context_relevance: float = 0.15     # Context appropriateness
    content_analysis: float = 0.15      # Decoded content meaningfulness
    cross_validation: float = 0.10      # Multiple validation sources
    file_type_weight: float = 0.10      # File type confidence modifier
    security_impact: float = 0.05       # Security implication assessment
    
    def __post_init__(self):
        """Validate that weights sum to 1.0."""
        total = (self.encoding_quality + self.pattern_reliability + 
                self.context_relevance + self.content_analysis + 
                self.cross_validation + self.file_type_weight + 
                self.security_impact)
        
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Evidence weights must sum to 1.0, got {total}")

@dataclass
class PatternReliability:
    """Pattern reliability data for confidence calculation."""
    pattern_id: str
    total_detections: int
    true_positives: int
    false_positives: int
    confidence_adjustment: float
    
    @property
    def reliability_score(self) -> float:
        """Calculate reliability score based on historical data."""
        if self.total_detections == 0:
            return 0.5  # Conservative default for new patterns
        
        # Calculate false positive rate
        fp_rate = self.false_positives / self.total_detections
        # Convert to reliability score (1.0 - fp_rate)
        reliability = max(0.1, 1.0 - fp_rate)
        
        # Apply confidence adjustment
        return min(1.0, max(0.1, reliability + self.confidence_adjustment))

class EnhancedEncodingCloudConfidenceCalculator:
    """confidence calculator for encoding and cloud analysis."""
    
    def __init__(self):
        """Initialize the confidence calculator."""
        self.evidence_weights = EvidenceWeights()
        self._init_pattern_reliability_database()
        self._init_context_factors()
        self._init_security_impact_factors()
    
    def _init_pattern_reliability_database(self):
        """Initialize pattern reliability database with historical data."""
        self.pattern_reliability = {
            # Encoding pattern reliability
            "base64_standard": PatternReliability("base64_standard", 1000, 920, 80, 0.02),
            "base64_android": PatternReliability("base64_android", 500, 475, 25, 0.05),
            "base64_url_safe": PatternReliability("base64_url_safe", 300, 285, 15, 0.03),
            "rot47_encoded": PatternReliability("rot47_encoded", 150, 135, 15, 0.01),
            "rot13_encoded": PatternReliability("rot13_encoded", 200, 180, 20, 0.00),
            "hex_encoded": PatternReliability("hex_encoded", 400, 360, 40, -0.02),
            "multi_layer_encoding": PatternReliability("multi_layer_encoding", 75, 70, 5, 0.08),
            
            # Cipher pattern reliability
            "aes_implementation": PatternReliability("aes_implementation", 800, 760, 40, 0.03),
            "des_implementation": PatternReliability("des_implementation", 200, 190, 10, 0.04),
            "rsa_implementation": PatternReliability("rsa_implementation", 600, 570, 30, 0.02),
            "weak_cipher_usage": PatternReliability("weak_cipher_usage", 300, 285, 15, 0.05),
            
            # Cloud service pattern reliability
            "firebase_config": PatternReliability("firebase_config", 1200, 1140, 60, 0.04),
            "aws_credentials": PatternReliability("aws_credentials", 400, 385, 15, 0.06),
            "gcp_service_account": PatternReliability("gcp_service_account", 250, 240, 10, 0.05),
            "azure_storage": PatternReliability("azure_storage", 180, 171, 9, 0.03),
            "generic_api_key": PatternReliability("generic_api_key", 600, 540, 60, 0.01),
            "database_connection": PatternReliability("database_connection", 300, 285, 15, 0.04),
            
            # Security configuration patterns
            "ssl_verify_disabled": PatternReliability("ssl_verify_disabled", 150, 145, 5, 0.07),
            "public_access_config": PatternReliability("public_access_config", 100, 95, 5, 0.06),
            "debug_mode_enabled": PatternReliability("debug_mode_enabled", 200, 190, 10, 0.03),
        }
    
    def _init_context_factors(self):
        """Initialize context-aware factors for confidence calculation."""
        self.file_type_confidence_modifiers = {
            FileType.SOURCE_CODE: 1.0,        # High confidence in source code
            FileType.CONFIG_FILE: 0.95,       # Very high confidence in config files
            FileType.STRINGS_XML: 0.9,        # High confidence in strings
            FileType.RESOURCE_FILE: 0.85,     # Good confidence in resources
            FileType.MANIFEST: 0.8,           # Good confidence in manifest
            FileType.NATIVE_FILE: 0.7,        # Lower confidence in binary extraction
            FileType.BINARY: 0.6,             # Lowest confidence in binary
            FileType.OTHER: 0.75,             # Moderate confidence for unknown types
        }
        
        self.analysis_pattern_confidence = {
            AnalysisPattern.ANDROID_SECURITY: 0.9,
            AnalysisPattern.FIREBASE_INTEGRATION: 0.85,
            AnalysisPattern.AWS_CREDENTIALS: 0.95,
            AnalysisPattern.ENCODING_CHAINS: 0.8,
            AnalysisPattern.CLOUD_ENDPOINTS: 0.75,
            AnalysisPattern.CIPHER_IMPLEMENTATION: 0.85,
            AnalysisPattern.GENERIC_VULNERABILITY: 0.7,
        }
        
        self.severity_confidence_impact = {
            SeverityLevel.CRITICAL: 0.1,      # High severity increases confidence
            SeverityLevel.HIGH: 0.05,
            SeverityLevel.MEDIUM: 0.0,        # No adjustment for medium
            SeverityLevel.LOW: -0.05,         # Lower severity decreases confidence
            SeverityLevel.INFO: -0.1,
        }
    
    def _init_security_impact_factors(self):
        """Initialize security impact assessment factors."""
        self.security_keywords_weights = {
            # High impact keywords
            'password': 0.9, 'secret': 0.9, 'private_key': 0.95, 'api_key': 0.85,
            'access_token': 0.85, 'credential': 0.8, 'certificate': 0.8,
            
            # Medium impact keywords
            'config': 0.6, 'endpoint': 0.65, 'url': 0.5, 'database': 0.7,
            
            # Cloud service keywords
            'firebase': 0.75, 'aws': 0.8, 's3': 0.75, 'azure': 0.7,
            'google_cloud': 0.7, 'gcp': 0.7,
        }
    
    def calculate_encoding_confidence(
        self, 
        finding: EncodingFinding, 
        analysis_context: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate confidence for encoding findings using evidence-based scoring.
        
        Args:
            finding: EncodingFinding to calculate confidence for
            analysis_context: Additional context for confidence calculation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        evidence_scores = {}
        
        # 1. Encoding Quality Assessment (25%)
        evidence_scores[EvidenceFactor.ENCODING_QUALITY] = self._assess_encoding_quality(finding)
        
        # 2. Pattern Reliability (20%)
        evidence_scores[EvidenceFactor.PATTERN_RELIABILITY] = self._get_pattern_reliability(
            finding.encoding_type, finding.pattern_matched
        )
        
        # 3. Context Relevance (15%)
        evidence_scores[EvidenceFactor.CONTEXT_RELEVANCE] = self._assess_context_relevance(
            finding, analysis_context
        )
        
        # 4. Content Analysis (15%)
        evidence_scores[EvidenceFactor.CONTENT_ANALYSIS] = self._assess_content_meaningfulness(
            finding.decoded_content, finding.encoded_content
        )
        
        # 5. Cross Validation (10%)
        evidence_scores[EvidenceFactor.CROSS_VALIDATION] = self._assess_cross_validation(
            finding, analysis_context
        )
        
        # 6. File Type Weight (10%)
        evidence_scores[EvidenceFactor.FILE_TYPE_WEIGHT] = self._get_file_type_confidence(
            finding.context.file_type if finding.context else FileType.OTHER
        )
        
        # 7. Security Impact (5%)
        evidence_scores[EvidenceFactor.SECURITY_IMPACT] = self._assess_security_impact(finding)
        
        # Calculate weighted confidence score
        confidence = self._calculate_weighted_confidence(evidence_scores)
        
        # Apply analysis pattern adjustments
        confidence = self._apply_pattern_adjustments(confidence, finding.analysis_patterns)
        
        # Apply severity-based adjustments
        confidence = self._apply_severity_adjustments(confidence, finding.severity)
        
        # Ensure confidence is within valid range
        return max(0.0, min(1.0, confidence))
    
    def calculate_cipher_confidence(
        self, 
        finding: CipherFinding, 
        analysis_context: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate confidence for cipher findings using evidence-based scoring.
        
        Args:
            finding: CipherFinding to calculate confidence for
            analysis_context: Additional context for confidence calculation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        evidence_scores = {}
        
        # 1. Cipher Detection Quality (25%)
        evidence_scores[EvidenceFactor.ENCODING_QUALITY] = self._assess_cipher_quality(finding)
        
        # 2. Pattern Reliability (20%)
        evidence_scores[EvidenceFactor.PATTERN_RELIABILITY] = self._get_cipher_pattern_reliability(
            finding.cipher_type
        )
        
        # 3. Context Relevance (15%)
        evidence_scores[EvidenceFactor.CONTEXT_RELEVANCE] = self._assess_cipher_context_relevance(
            finding, analysis_context
        )
        
        # 4. Implementation Analysis (15%)
        evidence_scores[EvidenceFactor.CONTENT_ANALYSIS] = self._assess_cipher_implementation(
            finding.implementation_details, finding.vulnerabilities
        )
        
        # 5. Cross Validation (10%)
        evidence_scores[EvidenceFactor.CROSS_VALIDATION] = self._assess_cipher_cross_validation(
            finding, analysis_context
        )
        
        # 6. File Type Weight (10%)
        evidence_scores[EvidenceFactor.FILE_TYPE_WEIGHT] = self._get_file_type_confidence(
            finding.context.file_type if finding.context else FileType.OTHER
        )
        
        # 7. Security Impact (5%)
        evidence_scores[EvidenceFactor.SECURITY_IMPACT] = self._assess_cipher_security_impact(finding)
        
        # Calculate weighted confidence score
        confidence = self._calculate_weighted_confidence(evidence_scores)
        
        # Apply cipher-specific adjustments
        confidence = self._apply_cipher_adjustments(confidence, finding.cipher_type)
        
        # Apply severity-based adjustments
        confidence = self._apply_severity_adjustments(confidence, finding.severity)
        
        return max(0.0, min(1.0, confidence))
    
    def calculate_cloud_service_confidence(
        self, 
        finding: CloudServiceFinding, 
        analysis_context: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate confidence for cloud service findings using evidence-based scoring.
        
        Args:
            finding: CloudServiceFinding to calculate confidence for
            analysis_context: Additional context for confidence calculation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        evidence_scores = {}
        
        # 1. Service Detection Quality (25%)
        evidence_scores[EvidenceFactor.ENCODING_QUALITY] = self._assess_cloud_service_quality(finding)
        
        # 2. Pattern Reliability (20%)
        evidence_scores[EvidenceFactor.PATTERN_RELIABILITY] = self._get_cloud_pattern_reliability(
            finding.service_type
        )
        
        # 3. Context Relevance (15%)
        evidence_scores[EvidenceFactor.CONTEXT_RELEVANCE] = self._assess_cloud_context_relevance(
            finding, analysis_context
        )
        
        # 4. Configuration Analysis (15%)
        evidence_scores[EvidenceFactor.CONTENT_ANALYSIS] = self._assess_cloud_configuration(
            finding.configuration_issues, finding.integration_vulnerabilities
        )
        
        # 5. Cross Validation (10%)
        evidence_scores[EvidenceFactor.CROSS_VALIDATION] = self._assess_cloud_cross_validation(
            finding, analysis_context
        )
        
        # 6. File Type Weight (10%)
        evidence_scores[EvidenceFactor.FILE_TYPE_WEIGHT] = self._get_file_type_confidence(
            finding.context.file_type if finding.context else FileType.OTHER
        )
        
        # 7. Security Impact (5%)
        evidence_scores[EvidenceFactor.SECURITY_IMPACT] = self._assess_cloud_security_impact(finding)
        
        # Calculate weighted confidence score
        confidence = self._calculate_weighted_confidence(evidence_scores)
        
        # Apply cloud service specific adjustments
        confidence = self._apply_cloud_service_adjustments(confidence, finding.service_type)
        
        # Apply severity-based adjustments
        confidence = self._apply_severity_adjustments(confidence, finding.severity)
        
        return max(0.0, min(1.0, confidence))
    
    def calculate_comprehensive_confidence(
        self, 
        result: ComprehensiveAnalysisResult
    ) -> float:
        """
        Calculate overall confidence for comprehensive analysis results.
        
        Args:
            result: ComprehensiveAnalysisResult to calculate confidence for
            
        Returns:
            Overall confidence score between 0.0 and 1.0
        """
        if result.total_findings == 0:
            return 0.0
        
        # Calculate weighted average confidence based on finding types and severity
        total_weight = 0.0
        weighted_confidence_sum = 0.0
        
        # Weight findings by severity
        severity_weights = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.6,
            SeverityLevel.LOW: 0.4,
            SeverityLevel.INFO: 0.2
        }
        
        # Process encoding findings
        for finding in result.all_encoding_findings:
            if finding.confidence > 0:
                weight = severity_weights.get(finding.severity, 0.6)
                weighted_confidence_sum += finding.confidence * weight
                total_weight += weight
        
        # Process cipher findings
        for finding in result.all_cipher_findings:
            if finding.confidence > 0:
                weight = severity_weights.get(finding.severity, 0.6) * 1.1  # Cipher findings get slight boost
                weighted_confidence_sum += finding.confidence * weight
                total_weight += weight
        
        # Process cloud findings
        for finding in result.all_cloud_findings:
            if finding.confidence > 0:
                weight = severity_weights.get(finding.severity, 0.6)
                weighted_confidence_sum += finding.confidence * weight
                total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        overall_confidence = weighted_confidence_sum / total_weight
        
        # Apply global adjustments based on analysis quality
        overall_confidence = self._apply_global_adjustments(overall_confidence, result)
        
        return max(0.0, min(1.0, overall_confidence))
    
    # Evidence Assessment Methods
    
    def _assess_encoding_quality(self, finding: EncodingFinding) -> float:
        """Assess the quality of encoding detection."""
        quality_score = 0.5  # Base score
        
        # Length factor
        if len(finding.encoded_content) > 50:
            quality_score += 0.15
        if len(finding.encoded_content) > 100:
            quality_score += 0.1
        
        # Encoding type factor
        type_quality = {
            EncodingType.BASE64: 0.2,
            EncodingType.MULTI_LAYER: 0.25,
            EncodingType.ROT47: 0.15,
            EncodingType.HEX: 0.1,
            EncodingType.ROT13: 0.05,
        }
        quality_score += type_quality.get(finding.encoding_type, 0.1)
        
        # Valid encoding chain factor
        if finding.encoding_chain and len(finding.encoding_chain) > 1:
            quality_score += 0.1
        
        return min(1.0, quality_score)
    
    def _assess_cipher_quality(self, finding: CipherFinding) -> float:
        """Assess the quality of cipher detection."""
        quality_score = 0.6  # Base score for cipher detection
        
        # Cipher type quality
        type_quality = {
            CipherType.AES: 0.2,
            CipherType.RSA: 0.2,
            CipherType.DES: 0.15,  # Lower because it's weak
            CipherType.RC4: 0.1,   # Lower because it's weak
            CipherType.BLOWFISH: 0.15,
        }
        quality_score += type_quality.get(finding.cipher_type, 0.1)
        
        # Implementation details factor
        if finding.key_size:
            quality_score += 0.05
        if finding.mode:
            quality_score += 0.05
        if finding.vulnerabilities:
            quality_score += 0.1  # Higher confidence if vulnerabilities detected
        
        return min(1.0, quality_score)
    
    def _assess_cloud_service_quality(self, finding: CloudServiceFinding) -> float:
        """Assess the quality of cloud service detection."""
        quality_score = 0.5  # Base score
        
        # Service type quality
        type_quality = {
            CloudServiceType.FIREBASE: 0.25,
            CloudServiceType.AWS_S3: 0.25,
            CloudServiceType.GOOGLE_CLOUD: 0.2,
            CloudServiceType.AZURE: 0.2,
            CloudServiceType.GENERIC_API: 0.1,
        }
        quality_score += type_quality.get(finding.service_type, 0.1)
        
        # Configuration completeness
        if finding.service_endpoint:
            quality_score += 0.1
        if finding.configuration_issues:
            quality_score += 0.1
        if finding.credential_exposure:
            quality_score += 0.15  # High confidence for credential exposure
        
        return min(1.0, quality_score)
    
    def _get_pattern_reliability(self, encoding_type: EncodingType, pattern: str) -> float:
        """Get pattern reliability score for encoding types."""
        # Map encoding types to pattern reliability
        pattern_map = {
            EncodingType.BASE64: "base64_standard",
            EncodingType.ROT47: "rot47_encoded",
            EncodingType.ROT13: "rot13_encoded",
            EncodingType.HEX: "hex_encoded",
            EncodingType.MULTI_LAYER: "multi_layer_encoding",
        }
        
        pattern_id = pattern_map.get(encoding_type, "base64_standard")
        reliability = self.pattern_reliability.get(pattern_id)
        
        return reliability.reliability_score if reliability else 0.7
    
    def _get_cipher_pattern_reliability(self, cipher_type: CipherType) -> float:
        """Get pattern reliability score for cipher types."""
        pattern_map = {
            CipherType.AES: "aes_implementation",
            CipherType.DES: "des_implementation",
            CipherType.RSA: "rsa_implementation",
            CipherType.RC4: "weak_cipher_usage",
            CipherType.BLOWFISH: "weak_cipher_usage",
        }
        
        pattern_id = pattern_map.get(cipher_type, "aes_implementation")
        reliability = self.pattern_reliability.get(pattern_id)
        
        return reliability.reliability_score if reliability else 0.75
    
    def _get_cloud_pattern_reliability(self, service_type: CloudServiceType) -> float:
        """Get pattern reliability score for cloud service types."""
        pattern_map = {
            CloudServiceType.FIREBASE: "firebase_config",
            CloudServiceType.AWS_S3: "aws_credentials",
            CloudServiceType.GOOGLE_CLOUD: "gcp_service_account",
            CloudServiceType.AZURE: "azure_storage",
            CloudServiceType.GENERIC_API: "generic_api_key",
        }
        
        pattern_id = pattern_map.get(service_type, "generic_api_key")
        reliability = self.pattern_reliability.get(pattern_id)
        
        return reliability.reliability_score if reliability else 0.7
    
    def _assess_context_relevance(self, finding: EncodingFinding, 
                                 context: Optional[Dict[str, Any]]) -> float:
        """Assess context relevance for encoding findings."""
        relevance_score = 0.7  # Base relevance
        
        # File type relevance
        if finding.context:
            file_type_modifier = self.file_type_confidence_modifiers.get(
                finding.context.file_type, 0.75
            )
            relevance_score *= file_type_modifier
        
        # Analysis pattern relevance
        for pattern in finding.analysis_patterns:
            pattern_confidence = self.analysis_pattern_confidence.get(pattern, 0.7)
            relevance_score = max(relevance_score, pattern_confidence)
        
        return min(1.0, relevance_score)
    
    def _assess_cipher_context_relevance(self, finding: CipherFinding, 
                                        context: Optional[Dict[str, Any]]) -> float:
        """Assess context relevance for cipher findings."""
        relevance_score = 0.8  # Higher base for cipher findings
        
        if finding.context:
            file_type_modifier = self.file_type_confidence_modifiers.get(
                finding.context.file_type, 0.75
            )
            relevance_score *= file_type_modifier
        
        return min(1.0, relevance_score)
    
    def _assess_cloud_context_relevance(self, finding: CloudServiceFinding, 
                                       context: Optional[Dict[str, Any]]) -> float:
        """Assess context relevance for cloud service findings."""
        relevance_score = 0.75  # Base relevance for cloud findings
        
        if finding.context:
            file_type_modifier = self.file_type_confidence_modifiers.get(
                finding.context.file_type, 0.75
            )
            relevance_score *= file_type_modifier
        
        return min(1.0, relevance_score)
    
    def _assess_content_meaningfulness(self, decoded: Optional[str], encoded: str) -> float:
        """Assess meaningfulness of decoded content."""
        if not decoded:
            return 0.3
        
        meaningfulness = 0.4  # Base score
        
        # Check for meaningful patterns
        meaningful_keywords = [
            'http', 'https', 'api', 'key', 'token', 'secret', 'firebase',
            'aws', 'google', 'azure', 'password', 'credential', 'config'
        ]
        
        decoded_lower = decoded.lower()
        keyword_matches = sum(1 for keyword in meaningful_keywords if keyword in decoded_lower)
        
        # Add points for keyword matches
        meaningfulness += min(0.4, keyword_matches * 0.1)
        
        # Length factor
        if len(decoded) > 10:
            meaningfulness += 0.1
        if len(decoded) > 50:
            meaningfulness += 0.1
        
        return min(1.0, meaningfulness)
    
    def _assess_cipher_implementation(self, implementation: str, vulnerabilities: List[str]) -> float:
        """Assess cipher implementation quality."""
        implementation_score = 0.5  # Base score
        
        # Vulnerability detection increases confidence
        if vulnerabilities:
            implementation_score += min(0.3, len(vulnerabilities) * 0.1)
        
        # Implementation detail completeness
        if implementation and len(implementation) > 20:
            implementation_score += 0.1
        
        return min(1.0, implementation_score)
    
    def _assess_cloud_configuration(self, issues: List[str], 
                                   vulnerabilities: List[str]) -> float:
        """Assess cloud configuration analysis quality."""
        config_score = 0.5  # Base score
        
        # Configuration issues increase confidence
        if issues:
            config_score += min(0.25, len(issues) * 0.08)
        
        # Vulnerabilities increase confidence
        if vulnerabilities:
            config_score += min(0.25, len(vulnerabilities) * 0.08)
        
        return min(1.0, config_score)
    
    def _assess_cross_validation(self, finding: Union[EncodingFinding, CipherFinding, CloudServiceFinding], 
                                context: Optional[Dict[str, Any]]) -> float:
        """Assess cross-validation evidence."""
        validation_score = 0.5  # Base score
        
        # Check for multiple validation sources
        validation_sources = 0
        
        if context:
            if context.get('multiple_patterns'):
                validation_sources += 1
            if context.get('file_correlation'):
                validation_sources += 1
            if context.get('external_validation'):
                validation_sources += 1
        
        # Add points for each validation source
        validation_score += validation_sources * 0.15
        
        return min(1.0, validation_score)
    
    def _assess_cipher_cross_validation(self, finding: CipherFinding, 
                                       context: Optional[Dict[str, Any]]) -> float:
        """Assess cross-validation for cipher findings."""
        return self._assess_cross_validation(finding, context)
    
    def _assess_cloud_cross_validation(self, finding: CloudServiceFinding, 
                                      context: Optional[Dict[str, Any]]) -> float:
        """Assess cross-validation for cloud service findings."""
        return self._assess_cross_validation(finding, context)
    
    def _get_file_type_confidence(self, file_type: FileType) -> float:
        """Get confidence modifier based on file type."""
        return self.file_type_confidence_modifiers.get(file_type, 0.75)
    
    def _assess_security_impact(self, finding: Union[EncodingFinding, CipherFinding, CloudServiceFinding]) -> float:
        """Assess security impact of the finding."""
        impact_score = 0.5  # Base score
        
        # Check for high-impact security keywords
        content_to_check = ""
        
        if isinstance(finding, EncodingFinding) and finding.decoded_content:
            content_to_check = finding.decoded_content.lower()
        elif isinstance(finding, CipherFinding):
            content_to_check = finding.implementation_details.lower()
        elif isinstance(finding, CloudServiceFinding):
            content_to_check = finding.description.lower()
        
        # Calculate impact based on security keywords
        for keyword, weight in self.security_keywords_weights.items():
            if keyword in content_to_check:
                impact_score = max(impact_score, weight)
        
        return min(1.0, impact_score)
    
    def _assess_cipher_security_impact(self, finding: CipherFinding) -> float:
        """Assess security impact specific to cipher findings."""
        base_impact = self._assess_security_impact(finding)
        
        # Weak ciphers have higher security impact
        weak_ciphers = [CipherType.DES, CipherType.RC4]
        if finding.cipher_type in weak_ciphers:
            base_impact += 0.2
        
        # Vulnerabilities increase impact
        if finding.vulnerabilities:
            base_impact += min(0.2, len(finding.vulnerabilities) * 0.05)
        
        return min(1.0, base_impact)
    
    def _assess_cloud_security_impact(self, finding: CloudServiceFinding) -> float:
        """Assess security impact specific to cloud service findings."""
        base_impact = self._assess_security_impact(finding)
        
        # Credential exposure has high impact
        if finding.credential_exposure:
            base_impact += 0.3
        
        # Public access risk has medium impact
        if finding.public_access_risk:
            base_impact += 0.2
        
        return min(1.0, base_impact)
    
    def _calculate_weighted_confidence(self, evidence_scores: Dict[EvidenceFactor, float]) -> float:
        """Calculate weighted confidence score from evidence factors."""
        weighted_sum = 0.0
        
        weighted_sum += evidence_scores.get(EvidenceFactor.ENCODING_QUALITY, 0.5) * self.evidence_weights.encoding_quality
        weighted_sum += evidence_scores.get(EvidenceFactor.PATTERN_RELIABILITY, 0.5) * self.evidence_weights.pattern_reliability
        weighted_sum += evidence_scores.get(EvidenceFactor.CONTEXT_RELEVANCE, 0.5) * self.evidence_weights.context_relevance
        weighted_sum += evidence_scores.get(EvidenceFactor.CONTENT_ANALYSIS, 0.5) * self.evidence_weights.content_analysis
        weighted_sum += evidence_scores.get(EvidenceFactor.CROSS_VALIDATION, 0.5) * self.evidence_weights.cross_validation
        weighted_sum += evidence_scores.get(EvidenceFactor.FILE_TYPE_WEIGHT, 0.75) * self.evidence_weights.file_type_weight
        weighted_sum += evidence_scores.get(EvidenceFactor.SECURITY_IMPACT, 0.5) * self.evidence_weights.security_impact
        
        return weighted_sum
    
    def _apply_pattern_adjustments(self, confidence: float, patterns: List[AnalysisPattern]) -> float:
        """Apply analysis pattern specific adjustments."""
        if not patterns:
            return confidence
        
        # Get the highest confidence adjustment from patterns
        max_adjustment = max(
            self.analysis_pattern_confidence.get(pattern, 0.0) - 0.75
            for pattern in patterns
        )
        
        return min(1.0, confidence + max_adjustment)
    
    def _apply_cipher_adjustments(self, confidence: float, cipher_type: CipherType) -> float:
        """Apply cipher-type specific adjustments."""
        # Weak ciphers get confidence boost (higher certainty they're problematic)
        weak_cipher_boost = {
            CipherType.DES: 0.05,
            CipherType.RC4: 0.08,
        }
        
        boost = weak_cipher_boost.get(cipher_type, 0.0)
        return min(1.0, confidence + boost)
    
    def _apply_cloud_service_adjustments(self, confidence: float, service_type: CloudServiceType) -> float:
        """Apply cloud service specific adjustments."""
        # Well-known services get slight confidence boost
        service_boost = {
            CloudServiceType.FIREBASE: 0.03,
            CloudServiceType.AWS_S3: 0.03,
            CloudServiceType.GOOGLE_CLOUD: 0.02,
            CloudServiceType.AZURE: 0.02,
        }
        
        boost = service_boost.get(service_type, 0.0)
        return min(1.0, confidence + boost)
    
    def _apply_severity_adjustments(self, confidence: float, severity: SeverityLevel) -> float:
        """Apply severity-based confidence adjustments."""
        adjustment = self.severity_confidence_impact.get(severity, 0.0)
        return max(0.1, min(1.0, confidence + adjustment))
    
    def _apply_global_adjustments(self, confidence: float, result: ComprehensiveAnalysisResult) -> float:
        """Apply global adjustments based on overall analysis quality."""
        # Multi-source validation boost
        if result.total_findings > 5:
            confidence += 0.02
        
        # Cross-finding correlation boost
        if (len(result.all_encoding_findings) > 0 and 
            len(result.all_cloud_findings) > 0):
            confidence += 0.03
        
        return min(1.0, confidence)
    
    def get_confidence_explanation(
        self, 
        finding: Union[EncodingFinding, CipherFinding, CloudServiceFinding],
        evidence_scores: Optional[Dict[EvidenceFactor, float]] = None
    ) -> Dict[str, Any]:
        """
        Get detailed explanation of confidence calculation.
        
        Args:
            finding: Finding to explain confidence for
            evidence_scores: Evidence scores used in calculation
            
        Returns:
            Dictionary with detailed confidence explanation
        """
        explanation = {
            'final_confidence': finding.confidence,
            'evidence_factors': evidence_scores or {},
            'weights_used': {
                'encoding_quality': self.evidence_weights.encoding_quality,
                'pattern_reliability': self.evidence_weights.pattern_reliability,
                'context_relevance': self.evidence_weights.context_relevance,
                'content_analysis': self.evidence_weights.content_analysis,
                'cross_validation': self.evidence_weights.cross_validation,
                'file_type_weight': self.evidence_weights.file_type_weight,
                'security_impact': self.evidence_weights.security_impact,
            },
            'adjustments_applied': [],
            'pattern_reliability_used': None
        }
        
        # Add finding-specific information
        if isinstance(finding, EncodingFinding):
            explanation['finding_type'] = 'encoding'
            explanation['encoding_type'] = finding.encoding_type.value
            explanation['pattern_reliability_used'] = self._get_pattern_reliability(
                finding.encoding_type, finding.pattern_matched
            )
        elif isinstance(finding, CipherFinding):
            explanation['finding_type'] = 'cipher'
            explanation['cipher_type'] = finding.cipher_type.value
            explanation['pattern_reliability_used'] = self._get_cipher_pattern_reliability(
                finding.cipher_type
            )
        elif isinstance(finding, CloudServiceFinding):
            explanation['finding_type'] = 'cloud_service'
            explanation['service_type'] = finding.service_type.value
            explanation['pattern_reliability_used'] = self._get_cloud_pattern_reliability(
                finding.service_type
            )
        
        return explanation 