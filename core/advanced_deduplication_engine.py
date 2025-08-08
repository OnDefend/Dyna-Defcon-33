#!/usr/bin/env python3
"""
Advanced Deduplication Engine

Sophisticated deduplication system that uses multiple fingerprinting strategies
to identify and intelligently merge duplicate vulnerabilities while preserving
the highest quality information from each source.
"""

import logging
import hashlib
import re
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)

@dataclass
class DuplicationGroup:
    """Group of duplicate vulnerabilities with merge strategy."""
    primary_vulnerability: Dict[str, Any]
    duplicates: List[Dict[str, Any]]
    fingerprint: str
    merge_reason: str
    confidence_score: float

class AdvancedDeduplicationEngine:
    """
    Advanced deduplication engine that uses multiple strategies to identify
    and merge duplicate vulnerabilities while preserving data quality.
    """
    
    def __init__(self):
        """Initialize the advanced deduplication engine."""
        
        # Similarity thresholds for different matching strategies
        self.similarity_thresholds = {
            'exact_location': 1.0,        # Exact file path and line number
            'fuzzy_location': 0.9,        # Same file, nearby lines (±5)
            'content_similarity': 0.85,    # Similar title and description
            'pattern_match': 0.9,         # Same vulnerability pattern/type
            'weak_similarity': 0.7        # Minimum threshold for consideration
        }
        
        # Weight factors for merging decisions
        self.merge_weights = {
            'confidence': 0.4,     # Higher confidence wins
            'source_priority': 0.3, # Some sources are more reliable
            'completeness': 0.2,   # More complete data wins
            'specificity': 0.1     # More specific findings win
        }
        
        # Source priority mapping (higher is better)
        self.source_priorities = {
            'Exact Location Analysis': 10,
            'Enhanced Pattern Detection': 9,
            'Main Security Report': 8,
            'Static Code Analysis': 7,
            'Dynamic Analysis': 6,
            'Parallel Scan': 5,
            'Generic Analysis': 3,
            'Unknown': 1
        }
        
        self.statistics = {
            'total_processed': 0,
            'exact_duplicates': 0,
            'fuzzy_duplicates': 0,
            'content_duplicates': 0,
            'pattern_duplicates': 0,
            'merged_groups': 0,
            'preserved_vulnerabilities': 0
        }
    
    def deduplicate_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform comprehensive deduplication of vulnerability list.
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            Deduplicated list with merged vulnerabilities
        """
        logger.info(f"🔄 Starting advanced deduplication of {len(vulnerabilities)} vulnerabilities...")
        
        self.statistics['total_processed'] = len(vulnerabilities)
        
        # Stage 1: Create multiple fingerprints for each vulnerability
        fingerprinted_vulns = self._create_fingerprints(vulnerabilities)
        
        # Stage 2: Group vulnerabilities by similarity
        similarity_groups = self._group_by_similarity(fingerprinted_vulns)
        
        # Stage 3: Merge groups intelligently
        deduplicated_vulns = self._merge_similarity_groups(similarity_groups)
        
        # Stage 4: Final validation and cleanup
        final_vulns = self._validate_merged_vulnerabilities(deduplicated_vulns)
        
        self.statistics['preserved_vulnerabilities'] = len(final_vulns)
        
        logger.info(f"✅ Deduplication complete:")
        logger.info(f"   Original: {len(vulnerabilities)} vulnerabilities")
        logger.info(f"   Deduplicated: {len(final_vulns)} vulnerabilities")
        logger.info(f"   Removed: {len(vulnerabilities) - len(final_vulns)} duplicates")
        logger.info(f"   Merge groups: {self.statistics['merged_groups']}")
        
        return final_vulns
    
    def _create_fingerprints(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create multiple fingerprints for each vulnerability for comparison."""
        
        fingerprinted_vulns = []
        
        for i, vuln in enumerate(vulnerabilities):
            # Add original index for tracking
            vuln['_original_index'] = i
            
            # Create multiple fingerprints
            fingerprints = {
                'exact_location': self._create_exact_location_fingerprint(vuln),
                'fuzzy_location': self._create_fuzzy_location_fingerprint(vuln),
                'content_hash': self._create_content_fingerprint(vuln),
                'pattern_type': self._create_pattern_fingerprint(vuln),
                'semantic_hash': self._create_semantic_fingerprint(vuln)
            }
            
            vuln['_fingerprints'] = fingerprints
            fingerprinted_vulns.append(vuln)
        
        return fingerprinted_vulns
    
    def _create_exact_location_fingerprint(self, vuln: Dict[str, Any]) -> str:
        """Create fingerprint based on exact file location."""
        file_path = vuln.get('file_path', '').strip()
        line_number = vuln.get('line_number', 0)
        vuln_type = vuln.get('vulnerability_type', vuln.get('category', '')).strip().lower()
        
        if file_path and line_number > 0:
            return f"exact:{file_path}:{line_number}:{vuln_type}"
        return ""
    
    def _create_fuzzy_location_fingerprint(self, vuln: Dict[str, Any]) -> str:
        """Create fingerprint for nearby locations in same file."""
        file_path = vuln.get('file_path', '').strip()
        line_number = vuln.get('line_number', 0)
        vuln_type = vuln.get('vulnerability_type', vuln.get('category', '')).strip().lower()
        
        if file_path and line_number > 0:
            # Group by file and vulnerability type, ignore exact line
            return f"fuzzy:{file_path}:{vuln_type}"
        return ""
    
    def _create_content_fingerprint(self, vuln: Dict[str, Any]) -> str:
        """Create fingerprint based on vulnerability content."""
        title = vuln.get('title', '').strip().lower()
        description = vuln.get('description', '').strip().lower()
        
        # Normalize text for comparison
        normalized_title = re.sub(r'[^\w\s]', '', title)
        normalized_title = re.sub(r'\s+', ' ', normalized_title).strip()
        
        # Create hash of normalized content
        content = f"{normalized_title}:{description[:100]}"  # Limit description length
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def _create_pattern_fingerprint(self, vuln: Dict[str, Any]) -> str:
        """Create fingerprint based on vulnerability pattern/type."""
        pattern_name = vuln.get('pattern_name', '').strip().lower()
        pattern_id = vuln.get('pattern_id', '').strip().lower()
        vuln_type = vuln.get('vulnerability_type', '').strip().lower()
        category = vuln.get('category', '').strip().lower()
        cwe_id = vuln.get('cwe_id', '').strip().lower()
        
        # Use the most specific identifier available
        if pattern_id:
            return f"pattern:{pattern_id}"
        elif pattern_name:
            return f"pattern:{pattern_name}"
        elif cwe_id:
            return f"cwe:{cwe_id}:{vuln_type}"
        elif vuln_type:
            return f"type:{vuln_type}"
        else:
            return f"category:{category}"
    
    def _create_semantic_fingerprint(self, vuln: Dict[str, Any]) -> str:
        """Create semantic fingerprint for similar vulnerabilities."""
        title = vuln.get('title', '').strip().lower()
        
        # Extract key semantic elements
        semantic_keywords = []
        
        # Common vulnerability keywords
        vuln_keywords = [
            'injection', 'xss', 'sqli', 'traversal', 'hardcoded', 'weak',
            'insecure', 'exposed', 'debug', 'cleartext', 'crypto', 'auth',
            'permission', 'intent', 'storage', 'network', 'privacy'
        ]
        
        for keyword in vuln_keywords:
            if keyword in title:
                semantic_keywords.append(keyword)
        
        # Extract technical terms
        technical_terms = re.findall(r'\b(api|url|ssl|tls|aes|rsa|md5|sha|des|certificate|key|token|session|cookie|header|parameter|database|sql|xml|json|http|https)\b', title)
        semantic_keywords.extend(technical_terms)
        
        # Create semantic hash
        semantic_content = ':'.join(sorted(set(semantic_keywords)))
        return hashlib.md5(semantic_content.encode()).hexdigest()[:12] if semantic_content else "generic"
    
    def _group_by_similarity(self, vulnerabilities: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Group vulnerabilities by similarity using multiple strategies."""
        
        # Track which vulnerabilities have been grouped
        grouped_indices = set()
        similarity_groups = []
        
        for i, vuln1 in enumerate(vulnerabilities):
            if i in grouped_indices:
                continue
            
            # Start a new group with this vulnerability
            current_group = [vuln1]
            grouped_indices.add(i)
            
            # Find similar vulnerabilities
            for j, vuln2 in enumerate(vulnerabilities[i+1:], i+1):
                if j in grouped_indices:
                    continue
                
                similarity_score, match_type = self._calculate_similarity(vuln1, vuln2)
                
                if similarity_score >= self.similarity_thresholds['weak_similarity']:
                    current_group.append(vuln2)
                    grouped_indices.add(j)
                    
                    # Update statistics
                    if match_type == 'exact_location':
                        self.statistics['exact_duplicates'] += 1
                    elif match_type == 'fuzzy_location':
                        self.statistics['fuzzy_duplicates'] += 1
                    elif match_type == 'content_similarity':
                        self.statistics['content_duplicates'] += 1
                    elif match_type == 'pattern_match':
                        self.statistics['pattern_duplicates'] += 1
            
            # Add group if it has more than one vulnerability
            if len(current_group) > 1:
                similarity_groups.append(current_group)
                self.statistics['merged_groups'] += 1
            else:
                # Single vulnerability, add to final list
                similarity_groups.append(current_group)
        
        return similarity_groups
    
    def _calculate_similarity(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any]) -> Tuple[float, str]:
        """Calculate similarity score between two vulnerabilities."""
        
        fp1 = vuln1.get('_fingerprints', {})
        fp2 = vuln2.get('_fingerprints', {})
        
        # Check exact location match (highest priority)
        if fp1.get('exact_location') and fp2.get('exact_location'):
            if fp1['exact_location'] == fp2['exact_location']:
                return 1.0, 'exact_location'
        
        # Check fuzzy location match
        if fp1.get('fuzzy_location') and fp2.get('fuzzy_location'):
            if fp1['fuzzy_location'] == fp2['fuzzy_location']:
                # Also check if line numbers are close
                line1 = vuln1.get('line_number', 0)
                line2 = vuln2.get('line_number', 0)
                if abs(line1 - line2) <= 5:  # Within 5 lines
                    return 0.95, 'fuzzy_location'
                else:
                    return 0.8, 'fuzzy_location'
        
        # Check pattern match
        if fp1.get('pattern_type') and fp2.get('pattern_type'):
            if fp1['pattern_type'] == fp2['pattern_type']:
                return 0.9, 'pattern_match'
        
        # Check content similarity
        if fp1.get('content_hash') and fp2.get('content_hash'):
            if fp1['content_hash'] == fp2['content_hash']:
                return 0.85, 'content_similarity'
        
        # Check semantic similarity
        if fp1.get('semantic_hash') and fp2.get('semantic_hash'):
            if fp1['semantic_hash'] == fp2['semantic_hash']:
                # Calculate text similarity for verification
                title1 = vuln1.get('title', '').lower()
                title2 = vuln2.get('title', '').lower()
                text_similarity = SequenceMatcher(None, title1, title2).ratio()
                
                if text_similarity >= 0.7:
                    return text_similarity, 'semantic_similarity'
        
        # Calculate overall similarity based on multiple factors
        similarity_factors = []
        
        # Title similarity
        title1 = vuln1.get('title', '').lower()
        title2 = vuln2.get('title', '').lower()
        title_sim = SequenceMatcher(None, title1, title2).ratio()
        similarity_factors.append(('title', title_sim, 0.4))
        
        # Category similarity
        cat1 = vuln1.get('category', '').lower()
        cat2 = vuln2.get('category', '').lower()
        cat_sim = 1.0 if cat1 == cat2 else 0.0
        similarity_factors.append(('category', cat_sim, 0.2))
        
        # Severity similarity
        sev1 = vuln1.get('severity', '').upper()
        sev2 = vuln2.get('severity', '').upper()
        sev_sim = 1.0 if sev1 == sev2 else 0.5
        similarity_factors.append(('severity', sev_sim, 0.1))
        
        # Description similarity (if available)
        desc1 = vuln1.get('description', '').lower()
        desc2 = vuln2.get('description', '').lower()
        if desc1 and desc2:
            desc_sim = SequenceMatcher(None, desc1[:200], desc2[:200]).ratio()
            similarity_factors.append(('description', desc_sim, 0.3))
        
        # Calculate weighted similarity
        total_weight = sum(weight for _, _, weight in similarity_factors)
        weighted_similarity = sum(score * weight for _, score, weight in similarity_factors) / total_weight
        
        return weighted_similarity, 'general_similarity'
    
    def _merge_similarity_groups(self, similarity_groups: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Merge similarity groups into single vulnerabilities."""
        
        merged_vulnerabilities = []
        
        for group in similarity_groups:
            if len(group) == 1:
                # No merging needed
                merged_vulns = group[0].copy()
                # Clean up temporary fields
                if '_fingerprints' in merged_vulns:
                    del merged_vulns['_fingerprints']
                if '_original_index' in merged_vulns:
                    del merged_vulns['_original_index']
                merged_vulnerabilities.append(merged_vulns)
            else:
                # Merge multiple vulnerabilities
                merged_vuln = self._merge_vulnerability_group(group)
                merged_vulnerabilities.append(merged_vuln)
        
        return merged_vulnerabilities
    
    def _merge_vulnerability_group(self, group: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge a group of similar vulnerabilities into one high-quality vulnerability."""
        
        # Select the best vulnerability as the base
        primary_vuln = self._select_primary_vulnerability(group)
        
        # Create merged vulnerability starting with primary
        merged_vuln = primary_vuln.copy()
        
        # Enhance with information from other vulnerabilities
        for vuln in group:
            if vuln != primary_vuln:
                merged_vuln = self._enhance_vulnerability_with_secondary(merged_vuln, vuln)
        
        # Add merge metadata
        merged_vuln['_merge_info'] = {
            'merged_count': len(group),
            'source_vulnerabilities': [v.get('id', f"vuln_{v.get('_original_index', 'unknown')}") for v in group],
            'merge_confidence': self._calculate_merge_confidence(group),
            'primary_source': primary_vuln.get('source', 'Unknown')
        }
        
        # Clean up temporary fields
        if '_fingerprints' in merged_vuln:
            del merged_vuln['_fingerprints']
        if '_original_index' in merged_vuln:
            del merged_vuln['_original_index']
        
        return merged_vuln
    
    def _select_primary_vulnerability(self, group: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Select the best vulnerability from a group to serve as the primary."""
        
        scored_vulns = []
        
        for vuln in group:
            score = 0.0
            
            # Confidence score (40% weight)
            confidence = vuln.get('confidence', 0.5)
            score += confidence * self.merge_weights['confidence']
            
            # Source priority (30% weight)
            source = vuln.get('source', 'Unknown')
            source_priority = self.source_priorities.get(source, 1)
            normalized_priority = source_priority / 10.0  # Normalize to 0-1
            score += normalized_priority * self.merge_weights['source_priority']
            
            # Data completeness (20% weight)
            completeness = self._calculate_completeness_score(vuln)
            score += completeness * self.merge_weights['completeness']
            
            # Specificity (10% weight)
            specificity = self._calculate_specificity_score(vuln)
            score += specificity * self.merge_weights['specificity']
            
            scored_vulns.append((score, vuln))
        
        # Return vulnerability with highest score
        return max(scored_vulns, key=lambda x: x[0])[1]
    
    def _calculate_completeness_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate completeness score for a vulnerability (0-1)."""
        
        score = 0.0
        total_fields = 10.0
        
        # Core fields
        if vuln.get('title'):
            score += 1.0
        if vuln.get('description'):
            score += 1.0
        if vuln.get('severity'):
            score += 1.0
        if vuln.get('confidence'):
            score += 1.0
        
        # Location information
        if vuln.get('file_path'):
            score += 1.5
        if vuln.get('line_number', 0) > 0:
            score += 1.0
        
        # Code context
        if vuln.get('matching_code'):
            score += 1.5
        
        # Standards compliance
        if vuln.get('masvs_controls'):
            score += 1.0
        if vuln.get('cwe_id'):
            score += 0.5
        
        # Additional context
        if vuln.get('remediation') or vuln.get('remediation_guidance'):
            score += 0.5
        
        return score / total_fields
    
    def _calculate_specificity_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate specificity score for a vulnerability (0-1)."""
        
        score = 0.0
        
        # Specific patterns score higher
        if vuln.get('pattern_id'):
            score += 0.3
        if vuln.get('pattern_name'):
            score += 0.2
        
        # Exact locations score higher
        if vuln.get('file_path') and vuln.get('line_number', 0) > 0:
            score += 0.3
        
        # Specific vulnerability types score higher
        vuln_type = vuln.get('vulnerability_type', '').lower()
        if vuln_type and vuln_type not in ['general', 'unknown', 'generic']:
            score += 0.2
        
        return min(1.0, score)
    
    def _enhance_vulnerability_with_secondary(self, primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance primary vulnerability with information from secondary."""
        
        enhanced = primary.copy()
        
        # Merge MASVS controls
        primary_controls = set(enhanced.get('masvs_controls', []))
        secondary_controls = set(secondary.get('masvs_controls', []))
        all_controls = primary_controls.union(secondary_controls)
        if all_controls:
            enhanced['masvs_controls'] = sorted(list(all_controls))
        
        # Use higher confidence if available
        if secondary.get('confidence', 0) > enhanced.get('confidence', 0):
            enhanced['confidence'] = secondary['confidence']
        
        # Merge descriptions if primary lacks detail
        primary_desc = enhanced.get('description', '')
        secondary_desc = secondary.get('description', '')
        if len(secondary_desc) > len(primary_desc):
            enhanced['description'] = secondary_desc
        
        # Add code context if missing
        if not enhanced.get('matching_code') and secondary.get('matching_code'):
            enhanced['matching_code'] = secondary['matching_code']
            enhanced['context_before'] = secondary.get('context_before', [])
            enhanced['context_after'] = secondary.get('context_after', [])
        
        # Merge evidence
        primary_evidence = enhanced.get('evidence', {})
        secondary_evidence = secondary.get('evidence', {})
        if secondary_evidence:
            merged_evidence = primary_evidence.copy()
            merged_evidence.update(secondary_evidence)
            enhanced['evidence'] = merged_evidence
        
        # Add CWE information if missing
        if not enhanced.get('cwe_id') and secondary.get('cwe_id'):
            enhanced['cwe_id'] = secondary['cwe_id']
        
        # Merge threat intelligence
        primary_threat = enhanced.get('threat_intelligence', {})
        secondary_threat = secondary.get('threat_intelligence', {})
        if secondary_threat:
            merged_threat = primary_threat.copy()
            merged_threat.update(secondary_threat)
            enhanced['threat_intelligence'] = merged_threat
        
        return enhanced
    
    def _calculate_merge_confidence(self, group: List[Dict[str, Any]]) -> float:
        """Calculate confidence in the merge decision."""
        
        if len(group) <= 1:
            return 1.0
        
        # Base confidence on similarity scores
        total_similarity = 0.0
        comparisons = 0
        
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                similarity, _ = self._calculate_similarity(group[i], group[j])
                total_similarity += similarity
                comparisons += 1
        
        avg_similarity = total_similarity / comparisons if comparisons > 0 else 0.5
        
        # Adjust for group size (larger groups need higher similarity)
        size_penalty = 1.0 - (len(group) - 2) * 0.1  # Penalty for large groups
        size_penalty = max(0.5, size_penalty)
        
        return avg_similarity * size_penalty
    
    def _validate_merged_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform final validation and cleanup of merged vulnerabilities."""
        
        validated_vulns = []
        
        for vuln in vulnerabilities:
            # Ensure required fields exist
            if not vuln.get('title'):
                vuln['title'] = f"Merged Vulnerability {len(validated_vulns) + 1}"
            
            if not vuln.get('severity'):
                vuln['severity'] = 'MEDIUM'
            
            if not vuln.get('confidence'):
                vuln['confidence'] = 0.7
            
            # Validate MASVS controls format
            if 'masvs_controls' in vuln:
                controls = vuln['masvs_controls']
                if isinstance(controls, list):
                    # Remove duplicates and invalid formats
                    valid_controls = []
                    for control in controls:
                        if isinstance(control, str) and re.match(r'^MASVS-[A-Z]+-\d+$', control.strip()):
                            valid_controls.append(control.strip())
                    vuln['masvs_controls'] = sorted(list(set(valid_controls)))
            
            # Add unique ID if missing
            if not vuln.get('id'):
                vuln['id'] = f"DEDUP-{len(validated_vulns) + 1:04d}"
            
            validated_vulns.append(vuln)
        
        return validated_vulns
    
    def get_deduplication_statistics(self) -> Dict[str, Any]:
        """Get comprehensive deduplication statistics."""
        return {
            'statistics': self.statistics.copy(),
            'thresholds': self.similarity_thresholds.copy(),
            'source_priorities': self.source_priorities.copy(),
            'processed_at': logger.handlers[0].formatter.formatTime(logger.handlers[0]._record, '%Y-%m-%d %H:%M:%S') if logger.handlers else 'unknown'
        }

def deduplicate_vulnerability_list(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convenience function for deduplicating vulnerability lists."""
    engine = AdvancedDeduplicationEngine()
    return engine.deduplicate_vulnerabilities(vulnerabilities) 