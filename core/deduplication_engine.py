#!/usr/bin/env python3
"""
AODS Advanced Deduplication Engine

Intelligent finding consolidation

Advanced deduplication system for vulnerability findings that eliminates
duplicate vulnerabilities while preserving unique security issues.
"""

import re
import logging
import hashlib
from typing import Dict, List, Any, Set, Tuple, Optional
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict, Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DuplicationType(Enum):
    EXACT = "EXACT"                 # Identical findings
    SIMILAR = "SIMILAR"             # Similar patterns/content
    RELATED = "RELATED"             # Related vulnerability types
    EVIDENCE = "EVIDENCE"           # Same evidence, different analysis

@dataclass
class DuplicationGroup:
    group_id: str
    primary_finding: Dict[str, Any]
    duplicate_findings: List[Dict[str, Any]]
    duplication_type: DuplicationType
    confidence_score: float
    consolidated_evidence: List[str]
    reasoning: List[str]

class DeduplicationEngine:
    """
    Advanced deduplication engine for vulnerability findings
    
    Implements intelligent grouping to:
    - Identify exact duplicates (same vulnerability, same location)
    - Group similar findings (same vulnerability type, different instances)
    - Consolidate related evidence from multiple analyzers
    - Create hierarchical reporting structure
    """
    
    def __init__(self):
        self.similarity_thresholds = self._load_similarity_thresholds()
        self.grouping_patterns = self._load_grouping_patterns()
        self.evidence_consolidators = self._load_evidence_consolidators()
        self.deduplication_rules = self._load_deduplication_rules()
        
        logger.info("Deduplication Engine initialized for intelligent finding consolidation")
    
    def _load_similarity_thresholds(self) -> Dict[str, float]:
        """Load similarity thresholds for different comparison types"""
        return {
            "exact_match": 0.95,        # 95% similarity for exact duplicates
            "similar_pattern": 0.80,    # 80% similarity for similar findings
            "related_vuln": 0.65,       # 65% similarity for related vulnerabilities
            "evidence_overlap": 0.70,   # 70% evidence overlap for consolidation
            "location_match": 0.90,     # 90% location similarity
            "content_similarity": 0.75  # 75% content similarity
        }
    
    def _load_grouping_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for grouping related findings"""
        return {
            "exported_components": [
                r"(?i)exported.*activity",
                r"(?i)exported.*service", 
                r"(?i)exported.*receiver",
                r"(?i)exported.*provider"
            ],
            
            "injection_vulnerabilities": [
                r"(?i)sql.*injection",
                r"(?i)command.*injection",
                r"(?i)code.*injection",
                r"(?i)script.*injection"
            ],
            
            "hardcoded_secrets": [
                r"(?i)hardcoded.*password",
                r"(?i)hardcoded.*api.*key",
                r"(?i)hardcoded.*secret",
                r"(?i)hardcoded.*token"
            ],
            
            "permission_issues": [
                r"(?i)dangerous.*permission",
                r"(?i)permission.*requested",
                r"(?i)permission.*granted",
                r"(?i)permission.*missing"
            ],
            
            "crypto_weaknesses": [
                r"(?i)weak.*encryption",
                r"(?i)weak.*hash",
                r"(?i)insecure.*random",
                r"(?i)deprecated.*crypto"
            ],
            
            "network_security": [
                r"(?i)cleartext.*traffic",
                r"(?i)certificate.*pinning",
                r"(?i)ssl.*verification",
                r"(?i)hostname.*verification"
            ]
        }
    
    def _load_evidence_consolidators(self) -> Dict[str, Dict]:
        """Load rules for consolidating evidence from multiple sources"""
        return {
            "location_based": {
                "weight": 0.4,
                "patterns": [
                    r"(?i)file:.*line:\d+",
                    r"(?i)class:.*method:",
                    r"(?i)component:.*activity:",
                    r"(?i)manifest:.*permission:"
                ]
            },
            
            "analyzer_based": {
                "weight": 0.3,
                "patterns": [
                    r"(?i)static.*analysis",
                    r"(?i)dynamic.*analysis", 
                    r"(?i)manifest.*analysis",
                    r"(?i)bytecode.*analysis"
                ]
            },
            
            "severity_based": {
                "weight": 0.3,
                "patterns": [
                    r"(?i)critical.*vulnerability",
                    r"(?i)high.*risk",
                    r"(?i)medium.*risk",
                    r"(?i)low.*risk"
                ]
            }
        }
    
    def _load_deduplication_rules(self) -> Dict[str, Dict]:
        """Load specific deduplication rules for different vulnerability types"""
        return {
            "exact_duplicate_rules": {
                "title_similarity": 0.95,
                "content_similarity": 0.90,
                "location_similarity": 0.95,
                "category_match": True
            },
            
            "similar_finding_rules": {
                "title_similarity": 0.80,
                "content_similarity": 0.70,
                "pattern_overlap": 0.75,
                "category_match": True
            },
            
            "related_vulnerability_rules": {
                "vulnerability_type_match": True,
                "location_proximity": 0.60,
                "evidence_overlap": 0.50,
                "category_related": True
            }
        }
    
    def deduplicate_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Main deduplication function that processes all findings
        
        Args:
            findings: List of vulnerability findings to deduplicate
            
        Returns:
            Dictionary with deduplicated findings and statistics
        """
        
        logger.info(f"Starting deduplication of {len(findings)} findings")
        
        # Step 1: Create fingerprints for all findings
        fingerprinted_findings = self._create_fingerprints(findings)
        
        # Step 2: Group findings by similarity
        similarity_groups = self._group_by_similarity(fingerprinted_findings)
        
        # Step 3: Apply deduplication rules
        deduplication_groups = self._apply_deduplication_rules(similarity_groups)
        
        # Step 4: Consolidate evidence within groups
        consolidated_groups = self._consolidate_evidence(deduplication_groups)
        
        # Step 5: Generate final deduplicated results
        deduplicated_results = self._generate_deduplicated_results(consolidated_groups)
        
        # Step 6: Calculate statistics
        statistics = self._calculate_deduplication_statistics(findings, deduplicated_results)
        
        logger.info(f"Deduplication complete: {len(findings)} → {len(deduplicated_results['unique_findings'])} "
                   f"({statistics['reduction_percentage']:.1f}% reduction)")
        
        return {
            "unique_findings": deduplicated_results["unique_findings"],
            "duplication_groups": deduplicated_results["duplication_groups"],
            "statistics": statistics,
            "consolidation_report": deduplicated_results["consolidation_report"]
        }
    
    def _create_fingerprints(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create unique fingerprints for each finding to enable comparison"""
        
        fingerprinted_findings = []
        
        for i, finding in enumerate(findings):
            title = finding.get("title", "")
            content = str(finding.get("content", ""))
            category = finding.get("category", "")
            
            # Create content-based fingerprint
            content_hash = hashlib.md5(f"{title}{content}".encode()).hexdigest()[:16]
            
            # Create pattern-based fingerprint
            pattern_fingerprint = self._extract_pattern_fingerprint(title, content)
            
            # Create location-based fingerprint
            location_fingerprint = self._extract_location_fingerprint(content)
            
            enhanced_finding = finding.copy()
            enhanced_finding.update({
                "finding_id": f"finding_{i:04d}",
                "content_hash": content_hash,
                "pattern_fingerprint": pattern_fingerprint,
                "location_fingerprint": location_fingerprint,
                "normalized_title": self._normalize_text(title),
                "normalized_content": self._normalize_text(content)
            })
            
            fingerprinted_findings.append(enhanced_finding)
        
        return fingerprinted_findings
    
    def _extract_pattern_fingerprint(self, title: str, content: str) -> str:
        """Extract pattern-based fingerprint for similarity comparison"""
        
        combined_text = f"{title} {content}".lower()
        
        # Extract key vulnerability patterns
        patterns = []
        for pattern_group, pattern_list in self.grouping_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    patterns.append(pattern_group)
                    break
        
        # Create fingerprint from patterns
        pattern_fingerprint = "_".join(sorted(set(patterns)))
        return pattern_fingerprint if pattern_fingerprint else "generic"
    
    def _extract_location_fingerprint(self, content: str) -> str:
        """Extract location-based fingerprint for grouping by code location"""
        
        location_patterns = [
            r"(?i)file:\s*([^\s]+)",
            r"(?i)class:\s*([^\s]+)",
            r"(?i)method:\s*([^\s]+)",
            r"(?i)line:\s*(\d+)",
            r"(?i)component:\s*([^\s]+)"
        ]
        
        locations = []
        for pattern in location_patterns:
            matches = re.findall(pattern, content)
            if matches:
                locations.extend(matches)
        
        # Create location fingerprint
        location_fingerprint = "_".join(sorted(set(locations)))
        return location_fingerprint if location_fingerprint else "unknown_location"
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for comparison by removing noise and standardizing format"""
        
        # Convert to lowercase
        normalized = text.lower()
        
        # Remove common noise words
        noise_words = ["detected", "found", "analysis", "scan", "check", "result"]
        for word in noise_words:
            normalized = re.sub(rf"\b{word}\b", "", normalized)
        
        # Remove extra whitespace
        normalized = re.sub(r"\s+", " ", normalized).strip()
        
        # Remove special characters except important ones
        normalized = re.sub(r"[^\w\s\-\._:]", "", normalized)
        
        return normalized
    
    def _group_by_similarity(self, findings: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Group findings by similarity using multiple comparison methods"""
        
        similarity_groups = []
        processed_findings = set()
        
        for i, finding in enumerate(findings):
            if finding["finding_id"] in processed_findings:
                continue
            
            # Start new group with current finding
            current_group = [finding]
            processed_findings.add(finding["finding_id"])
            
            # Find similar findings
            for j, other_finding in enumerate(findings[i+1:], i+1):
                if other_finding["finding_id"] in processed_findings:
                    continue
                
                similarity_score = self._calculate_similarity(finding, other_finding)
                
                if similarity_score >= self.similarity_thresholds["similar_pattern"]:
                    current_group.append(other_finding)
                    processed_findings.add(other_finding["finding_id"])
            
            similarity_groups.append(current_group)
        
        return similarity_groups
    
    def _calculate_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """Calculate similarity score between two findings"""
        
        # Title similarity
        title_sim = self._text_similarity(
            finding1["normalized_title"], 
            finding2["normalized_title"]
        )
        
        # Content similarity
        content_sim = self._text_similarity(
            finding1["normalized_content"], 
            finding2["normalized_content"]
        )
        
        # Pattern fingerprint similarity
        pattern_sim = 1.0 if finding1["pattern_fingerprint"] == finding2["pattern_fingerprint"] else 0.0
        
        # Location fingerprint similarity
        location_sim = self._text_similarity(
            finding1["location_fingerprint"], 
            finding2["location_fingerprint"]
        )
        
        # Category similarity
        category_sim = 1.0 if finding1.get("category") == finding2.get("category") else 0.0
        
        # Weighted similarity score
        similarity_score = (
            title_sim * 0.25 +
            content_sim * 0.30 +
            pattern_sim * 0.25 +
            location_sim * 0.15 +
            category_sim * 0.05
        )
        
        return similarity_score
    
    def _text_similarity(self, text1: str, text2: str) -> float:
        """Calculate text similarity using simple token-based comparison"""
        
        if not text1 or not text2:
            return 0.0
        
        # Tokenize texts
        tokens1 = set(text1.split())
        tokens2 = set(text2.split())
        
        if not tokens1 or not tokens2:
            return 0.0
        
        # Calculate Jaccard similarity
        intersection = len(tokens1.intersection(tokens2))
        union = len(tokens1.union(tokens2))
        
        return intersection / union if union > 0 else 0.0
    
    def _apply_deduplication_rules(self, similarity_groups: List[List[Dict[str, Any]]]) -> List[DuplicationGroup]:
        """Apply deduplication rules to similarity groups"""
        
        deduplication_groups = []
        
        for group in similarity_groups:
            if len(group) == 1:
                # Single finding - no duplication
                dedup_group = DuplicationGroup(
                    group_id=f"group_{len(deduplication_groups):04d}",
                    primary_finding=group[0],
                    duplicate_findings=[],
                    duplication_type=DuplicationType.EXACT,
                    confidence_score=1.0,
                    consolidated_evidence=[],
                    reasoning=["Single unique finding"]
                )
                deduplication_groups.append(dedup_group)
            else:
                # Multiple findings - determine duplication type and primary
                primary_finding, duplicates, duplication_type, confidence = self._analyze_duplication_group(group)
                
                dedup_group = DuplicationGroup(
                    group_id=f"group_{len(deduplication_groups):04d}",
                    primary_finding=primary_finding,
                    duplicate_findings=duplicates,
                    duplication_type=duplication_type,
                    confidence_score=confidence,
                    consolidated_evidence=[],
                    reasoning=self._generate_duplication_reasoning(group, duplication_type)
                )
                deduplication_groups.append(dedup_group)
        
        return deduplication_groups
    
    def _analyze_duplication_group(self, group: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], DuplicationType, float]:
        """Analyze a group of similar findings to determine duplication characteristics"""
        
        # Calculate pairwise similarities
        similarities = []
        for i in range(len(group)):
            for j in range(i+1, len(group)):
                sim = self._calculate_similarity(group[i], group[j])
                similarities.append(sim)
        
        avg_similarity = sum(similarities) / len(similarities) if similarities else 0.0
        
        # Determine duplication type based on similarity
        if avg_similarity >= self.similarity_thresholds["exact_match"]:
            duplication_type = DuplicationType.EXACT
        elif avg_similarity >= self.similarity_thresholds["similar_pattern"]:
            duplication_type = DuplicationType.SIMILAR
        elif avg_similarity >= self.similarity_thresholds["related_vuln"]:
            duplication_type = DuplicationType.RELATED
        else:
            duplication_type = DuplicationType.EVIDENCE
        
        # Select primary finding (highest severity or most detailed)
        primary_finding = self._select_primary_finding(group)
        
        # Remaining findings are duplicates
        duplicates = [f for f in group if f["finding_id"] != primary_finding["finding_id"]]
        
        return primary_finding, duplicates, duplication_type, avg_similarity
    
    def _select_primary_finding(self, group: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Select the primary finding from a group based on quality metrics"""
        
        # Score each finding based on various quality metrics
        scored_findings = []
        
        for finding in group:
            score = 0.0
            
            # Content length (more detailed is better)
            content_length = len(str(finding.get("content", "")))
            score += min(content_length / 1000, 1.0) * 0.3
            
            # Severity classification (if available)
            severity = finding.get("severity_classification", {}).get("severity", "INFO")
            severity_scores = {"HIGH": 1.0, "MEDIUM": 0.7, "LOW": 0.4, "INFO": 0.1}
            score += severity_scores.get(severity, 0.1) * 0.4
            
            # Confidence score (if available)
            confidence = finding.get("confidence_assessment", {}).get("confidence_score", 0.5)
            score += confidence * 0.3
            
            scored_findings.append((finding, score))
        
        # Return finding with highest score
        return max(scored_findings, key=lambda x: x[1])[0]
    
    def _generate_duplication_reasoning(self, group: List[Dict[str, Any]], duplication_type: DuplicationType) -> List[str]:
        """Generate reasoning for why findings were grouped together"""
        
        reasoning = []
        
        if duplication_type == DuplicationType.EXACT:
            reasoning.append(f"Exact duplicates identified: {len(group)} identical findings")
        elif duplication_type == DuplicationType.SIMILAR:
            reasoning.append(f"Similar patterns detected: {len(group)} related findings")
        elif duplication_type == DuplicationType.RELATED:
            reasoning.append(f"Related vulnerabilities grouped: {len(group)} findings")
        else:
            reasoning.append(f"Evidence consolidation: {len(group)} findings with overlapping evidence")
        
        # Add pattern-based reasoning
        patterns = set()
        for finding in group:
            patterns.add(finding.get("pattern_fingerprint", "unknown"))
        
        if len(patterns) == 1 and "unknown" not in patterns:
            reasoning.append(f"Common vulnerability pattern: {patterns.pop()}")
        
        return reasoning
    
    def _consolidate_evidence(self, deduplication_groups: List[DuplicationGroup]) -> List[DuplicationGroup]:
        """Consolidate evidence within each deduplication group"""
        
        for group in deduplication_groups:
            if group.duplicate_findings:
                # Collect evidence from all findings in the group
                all_findings = [group.primary_finding] + group.duplicate_findings
                consolidated_evidence = self._merge_evidence(all_findings)
                group.consolidated_evidence = consolidated_evidence
        
        return deduplication_groups
    
    def _merge_evidence(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Merge evidence from multiple findings"""
        
        evidence_items = []
        
        for finding in findings:
            # Extract evidence from different fields
            title = finding.get("title", "")
            content = str(finding.get("content", ""))
            
            # Add title as evidence
            if title and title not in evidence_items:
                evidence_items.append(f"Finding: {title}")
            
            # Extract specific evidence patterns
            evidence_patterns = [
                r"(?i)(file:\s*[^\s]+)",
                r"(?i)(class:\s*[^\s]+)",
                r"(?i)(method:\s*[^\s]+)",
                r"(?i)(line:\s*\d+)",
                r"(?i)(vulnerability:\s*[^\n]+)"
            ]
            
            for pattern in evidence_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if match not in evidence_items:
                        evidence_items.append(match)
        
        return evidence_items[:10]  # Limit to top 10 evidence items
    
    def _generate_deduplicated_results(self, deduplication_groups: List[DuplicationGroup]) -> Dict[str, Any]:
        """Generate final deduplicated results"""
        
        unique_findings = []
        duplication_groups_info = []
        
        for group in deduplication_groups:
            # Add primary finding to unique findings
            enhanced_primary = group.primary_finding.copy()
            enhanced_primary["deduplication_info"] = {
                "group_id": group.group_id,
                "duplicate_count": len(group.duplicate_findings),
                "duplication_type": group.duplication_type.value,
                "confidence_score": group.confidence_score,
                "consolidated_evidence": group.consolidated_evidence
            }
            unique_findings.append(enhanced_primary)
            
            # Add group information
            if group.duplicate_findings:
                group_info = {
                    "group_id": group.group_id,
                    "primary_finding_id": group.primary_finding["finding_id"],
                    "duplicate_finding_ids": [f["finding_id"] for f in group.duplicate_findings],
                    "duplication_type": group.duplication_type.value,
                    "confidence_score": group.confidence_score,
                    "reasoning": group.reasoning,
                    "consolidated_evidence": group.consolidated_evidence
                }
                duplication_groups_info.append(group_info)
        
        consolidation_report = self._generate_consolidation_report(deduplication_groups)
        
        return {
            "unique_findings": unique_findings,
            "duplication_groups": duplication_groups_info,
            "consolidation_report": consolidation_report
        }
    
    def _generate_consolidation_report(self, deduplication_groups: List[DuplicationGroup]) -> str:
        """Generate human-readable consolidation report"""
        
        total_groups = len(deduplication_groups)
        groups_with_duplicates = len([g for g in deduplication_groups if g.duplicate_findings])
        total_duplicates = sum(len(g.duplicate_findings) for g in deduplication_groups)
        
        # Count by duplication type
        type_counts = Counter(g.duplication_type.value for g in deduplication_groups if g.duplicate_findings)
        
        report = "ADVANCED DEDUPLICATION CONSOLIDATION REPORT\n"
        report += "=" * 50 + "\n\n"
        report += "CONSOLIDATION SUMMARY:\n"
        report += f"   Total Groups: {total_groups}\n"
        report += f"   Groups with Duplicates: {groups_with_duplicates}\n"
        report += f"   Total Duplicates Removed: {total_duplicates}\n\n"
        report += "DUPLICATION TYPE BREAKDOWN:\n"
        for dup_type, count in type_counts.items():
            report += f"   {dup_type}: {count} groups\n"
        report += "\nCONSOLIDATION BENEFITS:\n"
        report += "   • Eliminated redundant findings\n"
        report += "   • Consolidated evidence from multiple sources\n"
        report += "   • Created hierarchical vulnerability structure\n"
        report += "   • Maintained full traceability\n"
        
        return report
    
    def _calculate_deduplication_statistics(self, original_findings: List[Dict], deduplicated_results: Dict) -> Dict[str, Any]:
        """Calculate deduplication statistics"""
        
        original_count = len(original_findings)
        deduplicated_count = len(deduplicated_results["unique_findings"])
        reduction_count = original_count - deduplicated_count
        reduction_percentage = (reduction_count / original_count * 100) if original_count > 0 else 0.0
        
        return {
            "original_findings": original_count,
            "deduplicated_findings": deduplicated_count,
            "duplicates_removed": reduction_count,
            "reduction_percentage": reduction_percentage,
            "duplication_groups": len(deduplicated_results["duplication_groups"]),
            "average_group_size": reduction_count / len(deduplicated_results["duplication_groups"]) if deduplicated_results["duplication_groups"] else 0
        }

def main():
    """Demonstrate deduplication engine capabilities"""
    
    print("AODS Advanced Deduplication Engine")
    print("=" * 50)
    print("Intelligent finding consolidation")
    print("Target: 80% reduction through pattern grouping")
    print("=" * 50)
    
    # Initialize deduplication engine
    dedup_engine = DeduplicationEngine()
    
    # Test with realistic duplicate findings
    test_findings = [
        # Exact duplicates
        {
            "title": "Exported Activity without Permission",
            "content": "Activity MainActivity is exported without permission protection in AndroidManifest.xml",
            "category": "MASVS-PLATFORM"
        },
        {
            "title": "Exported Activity without Permission Protection",
            "content": "Activity MainActivity is exported without permission protection in AndroidManifest.xml",
            "category": "MASVS-PLATFORM"
        },
        
        # Similar findings
        {
            "title": "Exported Service without Permission",
            "content": "Service BackgroundService is exported without permission protection",
            "category": "MASVS-PLATFORM"
        },
        {
            "title": "Exported Receiver without Permission",
            "content": "BroadcastReceiver NotificationReceiver is exported without permission protection",
            "category": "MASVS-PLATFORM"
        },
        
        # Related vulnerabilities
        {
            "title": "Hardcoded API Key in Source",
            "content": "API key sk_live_1234567890 found hardcoded in MainActivity.java line 45",
            "category": "MASVS-STORAGE"
        },
        {
            "title": "Hardcoded Password Detected",
            "content": "Password 'admin123' found hardcoded in LoginActivity.java line 78",
            "category": "MASVS-STORAGE"
        },
        
        # Unique finding
        {
            "title": "Cleartext Traffic Allowed",
            "content": "Application allows cleartext HTTP traffic in network security config",
            "category": "MASVS-NETWORK"
        }
    ]
    
    # Apply deduplication
    results = dedup_engine.deduplicate_findings(test_findings)
    
    # Display results
    print(f"\nDEDUPLICATION RESULTS:")
    print(f"Original findings: {results['statistics']['original_findings']}")
    print(f"Unique findings: {results['statistics']['deduplicated_findings']}")
    print(f"Reduction: {results['statistics']['reduction_percentage']:.1f}%")
    print(f"Duplication groups: {results['statistics']['duplication_groups']}")
    
    print(f"\n{results['consolidation_report']}")
    
    print("DEDUPLICATION ENGINE IMPLEMENTED!")
    print("Ready for integration with filtering and confidence systems")
    print("Advanced accuracy components implemented!")

if __name__ == "__main__":
    main() 