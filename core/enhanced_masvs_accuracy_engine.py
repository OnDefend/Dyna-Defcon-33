#!/usr/bin/env python3
"""
Enhanced MASVS Accuracy Engine

Advanced MASVS mapping system that ensures accurate control assignments,
prevents over-tagging, and validates mappings against actual vulnerability content.
"""

import logging
import re
from typing import Dict, List, Any, Set, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class MAMVSMapping:
    """MASVS control mapping with confidence score."""
    control_id: str
    category: str
    relevance_score: float
    evidence: List[str]
    mapping_reason: str

@dataclass
class MAVSValidationResult:
    """Result of MASVS mapping validation."""
    is_valid: bool
    confidence_score: float
    validated_controls: List[str]
    removed_controls: List[str]
    evidence: Dict[str, List[str]]
    warnings: List[str]

class EnhancedMASVSAccuracyEngine:
    """
    Enhanced MASVS accuracy engine that provides precise control mappings
    based on actual vulnerability content and prevents over-tagging.
    """
    
    def __init__(self):
        """Initialize the enhanced MASVS accuracy engine."""
        
        # Comprehensive MASVS control definitions with keywords
        self.masvs_control_patterns = {
            # MASVS-STORAGE: Data Storage and Privacy Requirements
            'MASVS-STORAGE-1': {
                'keywords': ['storage', 'sensitive data', 'personally identifiable', 'pii', 'credentials', 'file system', 'database', 'preferences'],
                'code_patterns': ['SharedPreferences', 'openFileOutput', 'SQLiteDatabase', 'File(', 'FileOutputStream'],
                'negative_keywords': ['network', 'communication', 'crypto', 'authentication'],
                'category': 'Storage'
            },
            'MASVS-STORAGE-2': {
                'keywords': ['keyboard cache', 'clipboard', 'logs', 'crash reports', 'debug', 'auto-generated'],
                'code_patterns': ['Log.', 'System.out', 'printStackTrace', 'crash', 'clipboard'],
                'negative_keywords': ['intentional', 'required'],
                'category': 'Storage'
            },
            
            # MASVS-CRYPTO: Cryptography Requirements
            'MASVS-CRYPTO-1': {
                'keywords': ['cryptography', 'encryption', 'crypto', 'cipher', 'hash', 'key management', 'symmetric', 'asymmetric'],
                'code_patterns': ['Cipher', 'MessageDigest', 'KeyGenerator', 'SecretKey', 'crypto', 'encrypt', 'decrypt'],
                'negative_keywords': ['storage', 'network'],
                'category': 'Crypto'
            },
            'MASVS-CRYPTO-2': {
                'keywords': ['weak', 'outdated', 'deprecated', 'insecure', 'md5', 'sha1', 'des', 'rc4'],
                'code_patterns': ['MD5', 'SHA1', 'DES', 'RC4', 'ECB'],
                'negative_keywords': ['secure', 'recommended'],
                'category': 'Crypto'
            },
            
            # MASVS-AUTH: Authentication and Session Management
            'MASVS-AUTH-1': {
                'keywords': ['authentication', 'login', 'biometric', 'pin', 'password', 'multi-factor', 'mfa'],
                'code_patterns': ['BiometricPrompt', 'FingerprintManager', 'authenticate', 'login', 'password'],
                'negative_keywords': ['storage', 'crypto'],
                'category': 'Auth'
            },
            'MASVS-AUTH-2': {
                'keywords': ['session management', 'session', 'token', 'logout', 'timeout', 'expiration'],
                'code_patterns': ['session', 'token', 'expire', 'timeout', 'logout'],
                'negative_keywords': ['crypto', 'storage'],
                'category': 'Auth'
            },
            'MASVS-AUTH-3': {
                'keywords': ['authentication bypass', 'privilege escalation', 'authorization', 'access control'],
                'code_patterns': ['checkPermission', 'hasPermission', 'authorize', 'access'],
                'negative_keywords': ['crypto', 'storage'],
                'category': 'Auth'
            },
            
            # MASVS-NETWORK: Network Communication Requirements
            'MASVS-NETWORK-1': {
                'keywords': ['network', 'communication', 'tls', 'ssl', 'https', 'cleartext', 'http'],
                'code_patterns': ['HttpURLConnection', 'http://', 'cleartext', 'CLEARTEXT', 'setHostnameVerifier'],
                'negative_keywords': ['storage', 'crypto', 'authentication'],
                'category': 'Network'
            },
            'MASVS-NETWORK-2': {
                'keywords': ['certificate', 'pinning', 'trust', 'ssl context', 'hostname verification'],
                'code_patterns': ['X509TrustManager', 'HostnameVerifier', 'TrustManager', 'SSLContext'],
                'negative_keywords': ['storage', 'authentication'],
                'category': 'Network'
            },
            
            # MASVS-PLATFORM: Platform Integration Requirements
            'MASVS-PLATFORM-1': {
                'keywords': ['platform api', 'webview', 'javascript', 'deep links', 'url schemes'],
                'code_patterns': ['WebView', 'addJavascriptInterface', 'loadUrl', 'Intent', 'deeplink'],
                'negative_keywords': ['crypto', 'storage'],
                'category': 'Platform'
            },
            'MASVS-PLATFORM-2': {
                'keywords': ['ipc', 'intent', 'broadcast', 'content provider', 'service'],
                'code_patterns': ['Intent', 'BroadcastReceiver', 'ContentProvider', 'Service', 'PendingIntent'],
                'negative_keywords': ['network', 'crypto'],
                'category': 'Platform'
            },
            'MASVS-PLATFORM-3': {
                'keywords': ['custom keyboard', 'input method', 'accessibility', 'screen recording'],
                'code_patterns': ['InputMethodService', 'AccessibilityService', 'FLAG_SECURE'],
                'negative_keywords': ['crypto', 'network'],
                'category': 'Platform'
            },
            
            # MASVS-CODE: Code Quality and Build Setting Requirements
            'MASVS-CODE-1': {
                'keywords': ['binary protection', 'obfuscation', 'anti-debug', 'root detection', 'tampering'],
                'code_patterns': ['isDebuggable', 'checkSignature', 'anti-debug', 'root'],
                'negative_keywords': ['network', 'storage'],
                'category': 'Code'
            },
            'MASVS-CODE-2': {
                'keywords': ['debug', 'debugging', 'test code', 'development', 'staging'],
                'code_patterns': ['BuildConfig.DEBUG', 'Log.d', 'Log.v', '__android_log_print'],
                'negative_keywords': ['production', 'release'],
                'category': 'Code'
            },
            'MASVS-CODE-3': {
                'keywords': ['exception handling', 'error', 'sensitive information', 'stack trace'],
                'code_patterns': ['try', 'catch', 'Exception', 'printStackTrace', 'throw'],
                'negative_keywords': ['intentional', 'logged'],
                'category': 'Code'
            },
            'MASVS-CODE-4': {
                'keywords': ['third party', 'library', 'framework', 'dependency', 'vulnerable component'],
                'code_patterns': ['import', 'gradle', 'maven', 'library'],
                'negative_keywords': ['first party', 'internal'],
                'category': 'Code'
            },
            
            # MASVS-RESILIENCE: Anti-Reverse Engineering Requirements
            'MASVS-RESILIENCE-1': {
                'keywords': ['reverse engineering', 'static analysis', 'dynamic analysis', 'debugging'],
                'code_patterns': ['ptrace', 'debugger', 'anti-debug', 'obfuscation'],
                'negative_keywords': ['development', 'testing'],
                'category': 'Resilience'
            },
            'MASVS-RESILIENCE-2': {
                'keywords': ['runtime protection', 'hooking', 'instrumentation', 'frida', 'xposed'],
                'code_patterns': ['hook', 'instrument', 'runtime', 'native'],
                'negative_keywords': ['legitimate', 'testing'],
                'category': 'Resilience'
            }
        }
        
        # Vulnerability type to MASVS category mappings
        self.vulnerability_category_mappings = {
            'hardcoded_secret': ['Storage'],
            'insecure_storage': ['Storage'],
            'cleartext_storage': ['Storage'],
            'weak_crypto': ['Crypto'],
            'insecure_crypto': ['Crypto'],
            'authentication_bypass': ['Auth'],
            'session_management': ['Auth'],
            'cleartext_communication': ['Network'],
            'insecure_network': ['Network'],
            'certificate_pinning': ['Network'],
            'webview_security': ['Platform'],
            'intent_security': ['Platform'],
            'debug_enabled': ['Code'],
            'code_quality': ['Code'],
            'reverse_engineering': ['Resilience']
        }
        
        # Minimum confidence threshold for MASVS mapping
        self.minimum_mapping_confidence = 0.6
        
        # Maximum controls per vulnerability (to prevent over-tagging)
        self.max_controls_per_vulnerability = 3
        
        self.statistics = {
            'total_processed': 0,
            'accurate_mappings': 0,
            'over_tagged_prevented': 0,
            'low_confidence_removed': 0,
            'cross_validated': 0
        }
    
    def enhance_masvs_mappings(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enhance MASVS mappings with accuracy validation and over-tagging prevention.
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            Vulnerabilities with enhanced and validated MASVS mappings
        """
        logger.info(f"🏷️ Enhancing MASVS mappings for {len(vulnerabilities)} vulnerabilities...")
        
        self.statistics['total_processed'] = len(vulnerabilities)
        enhanced_vulnerabilities = []
        
        for vuln in vulnerabilities:
            try:
                enhanced_vuln = self._enhance_single_vulnerability_masvs(vuln)
                enhanced_vulnerabilities.append(enhanced_vuln)
                
                if enhanced_vuln.get('_masvs_enhanced'):
                    self.statistics['accurate_mappings'] += 1
                
            except Exception as e:
                logger.warning(f"Failed to enhance MASVS mapping for '{vuln.get('title', 'Unknown')}': {e}")
                enhanced_vulnerabilities.append(vuln)
        
        logger.info(f"✅ MASVS enhancement complete:")
        logger.info(f"   Accurate mappings: {self.statistics['accurate_mappings']}")
        logger.info(f"   Over-tagging prevented: {self.statistics['over_tagged_prevented']}")
        logger.info(f"   Low confidence removed: {self.statistics['low_confidence_removed']}")
        
        return enhanced_vulnerabilities
    
    def _enhance_single_vulnerability_masvs(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance MASVS mapping for a single vulnerability."""
        
        enhanced_vuln = vuln.copy()
        
        # Get existing MASVS controls if any
        existing_controls = vuln.get('masvs_controls', [])
        if isinstance(existing_controls, str):
            existing_controls = [c.strip() for c in existing_controls.split(',')]
        
        # Generate new accurate mappings
        new_mappings = self._generate_accurate_masvs_mappings(vuln)
        
        # Validate existing controls
        validated_result = self._validate_existing_masvs_controls(vuln, existing_controls)
        
        # Combine and deduplicate controls
        all_controls = set(validated_result.validated_controls)
        for mapping in new_mappings:
            if mapping.relevance_score >= self.minimum_mapping_confidence:
                all_controls.add(mapping.control_id)
        
        # Prevent over-tagging by selecting top controls
        final_controls = self._select_top_controls(list(all_controls), vuln, new_mappings)
        
        # Update vulnerability with enhanced MASVS information
        if final_controls:
            enhanced_vuln['masvs_controls'] = sorted(final_controls)
            enhanced_vuln['masvs_category'] = self._determine_primary_masvs_category(final_controls)
            enhanced_vuln['masvs_mapping_confidence'] = self._calculate_overall_mapping_confidence(final_controls, new_mappings)
            enhanced_vuln['_masvs_enhanced'] = True
            
            # Add mapping evidence if available
            evidence = {}
            for mapping in new_mappings:
                if mapping.control_id in final_controls:
                    evidence[mapping.control_id] = {
                        'relevance_score': mapping.relevance_score,
                        'evidence': mapping.evidence,
                        'reason': mapping.mapping_reason
                    }
            
            if evidence:
                enhanced_vuln['masvs_mapping_evidence'] = evidence
        
        # Add validation warnings if any
        if validated_result.warnings:
            enhanced_vuln['masvs_validation_warnings'] = validated_result.warnings
        
        # Track removed controls
        if validated_result.removed_controls:
            enhanced_vuln['masvs_removed_controls'] = validated_result.removed_controls
            self.statistics['over_tagged_prevented'] += len(validated_result.removed_controls)
        
        return enhanced_vuln
    
    def _generate_accurate_masvs_mappings(self, vuln: Dict[str, Any]) -> List[MAMVSMapping]:
        """Generate accurate MASVS mappings based on vulnerability content."""
        
        mappings = []
        
        # Get vulnerability content for analysis
        title = vuln.get('title', '').lower()
        description = vuln.get('description', '').lower()
        vuln_type = vuln.get('vulnerability_type', '').lower()
        category = vuln.get('category', '').lower()
        code = vuln.get('matching_code', '').lower()
        
        # Combined content for analysis
        all_content = f"{title} {description} {vuln_type} {category} {code}"
        
        # Check each MASVS control for relevance
        for control_id, control_info in self.masvs_control_patterns.items():
            relevance_score, evidence = self._calculate_control_relevance(
                control_id, control_info, all_content, vuln
            )
            
            if relevance_score > 0.3:  # Minimum threshold for consideration
                mapping_reason = self._generate_mapping_reason(control_id, evidence, relevance_score)
                
                mapping = MAMVSMapping(
                    control_id=control_id,
                    category=control_info['category'],
                    relevance_score=relevance_score,
                    evidence=evidence,
                    mapping_reason=mapping_reason
                )
                mappings.append(mapping)
        
        # Sort by relevance score
        mappings.sort(key=lambda m: m.relevance_score, reverse=True)
        
        return mappings
    
    def _calculate_control_relevance(self, control_id: str, control_info: Dict[str, Any], 
                                   content: str, vuln: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate relevance score for a specific MASVS control."""
        
        score = 0.0
        evidence = []
        
        # Check positive keywords
        keyword_matches = 0
        for keyword in control_info['keywords']:
            if keyword in content:
                keyword_matches += 1
                evidence.append(f"Keyword match: '{keyword}'")
                score += 0.2
        
        # Bonus for multiple keyword matches
        if keyword_matches > 1:
            score += 0.1 * (keyword_matches - 1)
        
        # Check code patterns
        code_matches = 0
        code_content = vuln.get('matching_code', '')
        if code_content:
            for pattern in control_info['code_patterns']:
                if pattern.lower() in code_content.lower():
                    code_matches += 1
                    evidence.append(f"Code pattern match: '{pattern}'")
                    score += 0.3  # Code patterns are stronger evidence
        
        # Check for negative keywords (reduce score)
        negative_matches = 0
        for neg_keyword in control_info.get('negative_keywords', []):
            if neg_keyword in content:
                negative_matches += 1
                score -= 0.15
        
        # Adjust score based on vulnerability type alignment
        vuln_type = vuln.get('vulnerability_type', '').lower()
        control_category = control_info['category'].lower()
        
        if vuln_type in self.vulnerability_category_mappings:
            expected_categories = [cat.lower() for cat in self.vulnerability_category_mappings[vuln_type]]
            if control_category in expected_categories:
                score += 0.25
                evidence.append(f"Category alignment: {control_category}")
            else:
                score -= 0.1  # Penalize misaligned categories
        
        # Check for specific vulnerability patterns
        if control_id == 'MASVS-STORAGE-1' and any(term in content for term in ['hardcoded', 'credentials', 'password']):
            score += 0.3
            evidence.append("Hardcoded credentials detected")
        
        if control_id == 'MASVS-NETWORK-1' and any(term in content for term in ['cleartext', 'http://', 'insecure']):
            score += 0.3
            evidence.append("Cleartext communication detected")
        
        if control_id == 'MASVS-CRYPTO-2' and any(term in content for term in ['md5', 'sha1', 'des', 'weak']):
            score += 0.3
            evidence.append("Weak cryptography detected")
        
        # Normalize score
        score = max(0.0, min(1.0, score))
        
        return score, evidence
    
    def _validate_existing_masvs_controls(self, vuln: Dict[str, Any], 
                                        existing_controls: List[str]) -> MAVSValidationResult:
        """Validate existing MASVS controls for accuracy."""
        
        validated_controls = []
        removed_controls = []
        evidence = {}
        warnings = []
        
        for control in existing_controls:
            if not control or not isinstance(control, str):
                continue
            
            control = control.strip()
            
            # Check if control ID is valid
            if not re.match(r'^MASVS-[A-Z]+-\d+$', control):
                warnings.append(f"Invalid MASVS control format: {control}")
                removed_controls.append(control)
                continue
            
            # Check if control exists in our patterns
            if control not in self.masvs_control_patterns:
                warnings.append(f"Unknown MASVS control: {control}")
                removed_controls.append(control)
                continue
            
            # Validate relevance
            control_info = self.masvs_control_patterns[control]
            content = f"{vuln.get('title', '')} {vuln.get('description', '')} {vuln.get('vulnerability_type', '')}"
            
            relevance_score, control_evidence = self._calculate_control_relevance(
                control, control_info, content.lower(), vuln
            )
            
            if relevance_score >= self.minimum_mapping_confidence:
                validated_controls.append(control)
                evidence[control] = control_evidence
                self.statistics['cross_validated'] += 1
            else:
                removed_controls.append(control)
                warnings.append(f"Low relevance for {control}: {relevance_score:.2f}")
                self.statistics['low_confidence_removed'] += 1
        
        confidence_score = len(validated_controls) / len(existing_controls) if existing_controls else 1.0
        
        return MAVSValidationResult(
            is_valid=len(removed_controls) == 0,
            confidence_score=confidence_score,
            validated_controls=validated_controls,
            removed_controls=removed_controls,
            evidence=evidence,
            warnings=warnings
        )
    
    def _select_top_controls(self, all_controls: List[str], vuln: Dict[str, Any], 
                           mappings: List[MAMVSMapping]) -> List[str]:
        """Select top MASVS controls to prevent over-tagging."""
        
        if len(all_controls) <= self.max_controls_per_vulnerability:
            return all_controls
        
        # Score each control
        control_scores = {}
        mapping_dict = {m.control_id: m for m in mappings}
        
        for control in all_controls:
            if control in mapping_dict:
                control_scores[control] = mapping_dict[control].relevance_score
            else:
                # Give existing controls a moderate score
                control_scores[control] = 0.7
        
        # Sort by score and take top N
        sorted_controls = sorted(control_scores.items(), key=lambda x: x[1], reverse=True)
        selected_controls = [control for control, score in sorted_controls[:self.max_controls_per_vulnerability]]
        
        if len(all_controls) > len(selected_controls):
            self.statistics['over_tagged_prevented'] += len(all_controls) - len(selected_controls)
        
        return selected_controls
    
    def _determine_primary_masvs_category(self, controls: List[str]) -> str:
        """Determine primary MASVS category from selected controls."""
        
        category_counts = defaultdict(int)
        
        for control in controls:
            if control in self.masvs_control_patterns:
                category = self.masvs_control_patterns[control]['category']
                category_counts[category] += 1
        
        if category_counts:
            primary_category = max(category_counts.items(), key=lambda x: x[1])[0]
            return f"MASVS-{primary_category.upper()}"
        
        return "MASVS-GENERAL"
    
    def _calculate_overall_mapping_confidence(self, controls: List[str], 
                                            mappings: List[MAMVSMapping]) -> float:
        """Calculate overall confidence in MASVS mappings."""
        
        if not controls:
            return 0.0
        
        mapping_dict = {m.control_id: m for m in mappings}
        
        total_confidence = 0.0
        for control in controls:
            if control in mapping_dict:
                total_confidence += mapping_dict[control].relevance_score
            else:
                total_confidence += 0.7  # Default for existing controls
        
        return total_confidence / len(controls)
    
    def _generate_mapping_reason(self, control_id: str, evidence: List[str], 
                                relevance_score: float) -> str:
        """Generate human-readable explanation for MASVS mapping."""
        
        if relevance_score >= 0.8:
            confidence_level = "High confidence"
        elif relevance_score >= 0.6:
            confidence_level = "Moderate confidence"
        else:
            confidence_level = "Low confidence"
        
        if evidence:
            evidence_summary = "; ".join(evidence[:2])  # Take top 2 pieces of evidence
            return f"{confidence_level} mapping based on: {evidence_summary}"
        else:
            return f"{confidence_level} mapping (score: {relevance_score:.2f})"
    
    def generate_masvs_accuracy_report(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive MASVS accuracy report."""
        
        # Count controls and categories
        all_controls = set()
        category_counts = defaultdict(int)
        confidence_scores = []
        over_tagged_before = 0
        accurate_mappings = 0
        
        for vuln in vulnerabilities:
            controls = vuln.get('masvs_controls', [])
            if isinstance(controls, str):
                controls = [c.strip() for c in controls.split(',')]
            
            for control in controls:
                if control:
                    all_controls.add(control)
                    if control in self.masvs_control_patterns:
                        category = self.masvs_control_patterns[control]['category']
                        category_counts[category] += 1
            
            # Check mapping quality
            mapping_confidence = vuln.get('masvs_mapping_confidence', 0.0)
            if mapping_confidence > 0:
                confidence_scores.append(mapping_confidence)
                if mapping_confidence >= self.minimum_mapping_confidence:
                    accurate_mappings += 1
            
            # Count removed controls (over-tagging prevention)
            removed_controls = vuln.get('masvs_removed_controls', [])
            over_tagged_before += len(removed_controls)
        
        # Calculate coverage
        total_possible_controls = len(self.masvs_control_patterns)
        coverage_percentage = (len(all_controls) / total_possible_controls) * 100
        
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        return {
            'total_vulnerabilities_with_masvs': len([v for v in vulnerabilities if v.get('masvs_controls')]),
            'unique_controls_mapped': len(all_controls),
            'total_possible_controls': total_possible_controls,
            'coverage_percentage': round(coverage_percentage, 1),
            'category_distribution': dict(category_counts),
            'average_mapping_confidence': round(avg_confidence, 3),
            'accurate_mappings': accurate_mappings,
            'over_tagged_prevented': over_tagged_before,
            'accuracy_statistics': self.statistics.copy(),
            'quality_score': round((accurate_mappings / len(vulnerabilities)) * 100, 1) if vulnerabilities else 0
        }

def enhance_masvs_accuracy(vulnerabilities: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Convenience function for enhancing MASVS accuracy."""
    engine = EnhancedMASVSAccuracyEngine()
    enhanced_vulnerabilities = engine.enhance_masvs_mappings(vulnerabilities)
    accuracy_report = engine.generate_masvs_accuracy_report(enhanced_vulnerabilities)
    return enhanced_vulnerabilities, accuracy_report 